const std = @import("std");
const MethodInfo = @import("src/MethodInfo.zig");
const FieldInfo = @import("src/FieldInfo.zig");
const ClassFile = @import("src/ClassFile.zig");
const AccessFlagsValue = ClassFile.AccessFlagsValue;
const ConstantPool = @import("src/ConstantPool.zig");
const RefInfo = ConstantPool.RefInfo;
const Entry = ConstantPool.Entry;
const attributes = @import("src/attributes.zig");
const AttributeInfo = attributes.AttributeInfo;
const ExceptionsAttribute = attributes.ExceptionsAttribute;
const CodeAttribute = attributes.CodeAttribute;
const Writer = std.io.BufferedWriter(4096, std.fs.File.Writer).Writer;
const ops = @import("src/bytecode/ops.zig");
const Operation = ops.Operation;

const Allocator = std.mem.Allocator;

const FileData = struct {
    path_buffer: [std.fs.MAX_PATH_BYTES]u8,
    path: []u8,
    data: []const u8,
    mtime: i128,

    fn free(it: FileData, allocator: std.mem.Allocator) void {
        _ = it;
        _ = allocator;
    }
};

fn readFileData(allocator: std.mem.Allocator, filename: []const u8, file_data: *FileData) !void {
    file_data.path = try std.fs.realpath(filename, &file_data.path_buffer);
    file_data.path_buffer[file_data.path.len] = 0;
    file_data.path = file_data.path_buffer[0..file_data.path.len];

    const file = try std.fs.openFileAbsolute(file_data.path, .{});
    const stat = try file.stat();
    file_data.mtime = stat.mtime;

    const max_bytes = 1024 * 4096 * 4095;
    file_data.data = try file.readToEndAlloc(allocator, max_bytes);
}

pub fn getFilename() []const u8 {
    if (std.os.argv.len < 2) {
        _ = std.io.getStdErr().writer().print("Specify a file\n", .{}) catch {};
        unreachable;
        //return error.FileNotFound;
    }
    const filename = std.os.argv[1];
    const filename_length = std.mem.len(filename);
    return filename[0..filename_length];
}

pub fn main() !void {
    const out = std.io.getStdOut().writer();
    var buf = std.io.bufferedWriter(out);
    const w = buf.writer();

    const filename = getFilename();

    const allocator = std.heap.page_allocator;
    var file_data: FileData = undefined;
    try readFileData(allocator, filename, &file_data);
    defer file_data.free(allocator);

    var stream = std.io.fixedBufferStream(file_data.data);
    const reader = stream.reader();

    var cf = try ClassFile.decode(allocator, reader);
    defer cf.deinit();

    try printVerbose(w, cf, file_data);
    try buf.flush();
}

fn printSimple(writer: Writer, cf: ClassFile) !void {
    try printCompiledFrom(cf, writer);
    try printClass(writer, cf);
}

fn printCompiledFrom(cf: ClassFile, writer: Writer) !void {
    for (cf.attributes.items) |attr| {
        switch (attr) {
            AttributeInfo.source_file => |source_file| {
                const source_file_index = source_file.source_file_index - 1;
                const entry = cf.constant_pool.entries.items[source_file_index];
                switch (entry) {
                    Entry.utf8 => |utf8| {
                        try writer.print("  Compiled from \"{s}\"\n", .{utf8.bytes});
                    },
                    else => unreachable,
                }
            },
            else => {},
        }
    }
}

fn readString(cp: *ConstantPool, index: u16) []u8 {
    const entry = cp.get(index);
    return switch (entry) {
        .utf8 => |utf8| utf8.bytes,
        .class => |class| readString(cp, class.name_index),
        else => unreachable,
    };
}

fn printClass(writer: Writer, cf: ClassFile) !void {
    const class_name = readString(cf.constant_pool, cf.this_class);
    try writer.print("public class {s} extends {d}", .{
        class_name,
        cf.this_class,
    });
    try writer.print(" {{\n", .{});
    for (cf.methods.items) |method| {
        printMethod(writer, class_name, method);
    }
    try writer.print("}}\n", .{});
}

fn isConstructor(name: []const u8) u8 {
    if (std.mem.eql(u8, name, "<init>")) {
        return 1;
    } else if (std.mem.eql(u8, name, "<clinit>")) {
        return 2;
    } else {
        return 0;
    }
}

fn skipArguments(descriptor: []u8) []u8 {
    var i: usize = 0;
    while (i < descriptor.len and descriptor[i] != ')') {
        i += 1;
    }

    if (i == descriptor.len - 1) {
        return descriptor;
    } else {
        return descriptor[i + 1 .. descriptor.len];
    }
}

fn printMethod(writer: Writer, cf: ClassFile, method: MethodInfo) !void {
    const class_name = readString(cf.constant_pool, cf.this_class);
    var name = method.getName().bytes;

    try printModifiers(writer, method);
    const descriptor = method.getDescriptor().bytes;

    const is_constructor = isConstructor(name);

    if (is_constructor == 0) {
        if (findSignature(method.attributes)) |signatureAttribute| {
            const signature = readString(cf.constant_pool, signatureAttribute.signature_index);
            try printEscapedSignature(writer, skipArguments(signature));
            try writer.print(" ", .{});
        } else {
            try printReturnType(writer, descriptor);
            try writer.print(" ", .{});
        }
    }

    if (is_constructor == 1) {
        name = class_name;
    } else if (is_constructor == 2) {
        try writer.print("{{}};\n", .{});
        return;
    }

    try printWithNamespace(writer, name);
    try printArguments(writer, descriptor);
    try printExceptions(writer, cf.constant_pool, method);
    try writer.print(";\n", .{});
}

fn printModifiers(writer: Writer, method: MethodInfo) !void {
    try writer.print("  ", .{});
    if (method.access_flags.flags.public) {
        try writer.print("public ", .{});
    }
    if (method.access_flags.flags.private) {
        try writer.print("private ", .{});
    }
    if (method.access_flags.flags.protected) {
        try writer.print("protected ", .{});
    }
    if (method.access_flags.flags.static) {
        try writer.print("static ", .{});
    }
    if (method.access_flags.flags.final) {
        try writer.print("final ", .{});
    }
}

fn getReturnType(descriptor: []const u8) []const u8 {
    var i = descriptor.len - 1;
    while (descriptor[i] != ')' and i > 1) {
        i -= 1;
    }
    return descriptor[i + 1 .. descriptor.len];
}

fn printReturnType(writer: Writer, descriptor: []const u8) !void {
    const return_type = getReturnType(descriptor);
    try printNormalizedType(writer, return_type);
}

fn printArguments(writer: Writer, descriptor: []const u8) !void {
    try writer.print("(", .{});
    var i: usize = 1;
    while (i < descriptor.len and descriptor[i] != ')') {
        const ch = descriptor[i];
        if (getSimpleType(ch)) |simple_type| {
            try writer.print("{s}", .{simple_type});
            i += 1;
        } else if (ch == 'L') {
            i += 1;
            const start: usize = i;
            while (descriptor[i] != ';') {
                i += 1;
            }
            const end = i;
            i += 1;
            const name = descriptor[start..end];
            try printWithNamespace(writer, name);
        } else if (ch == '[') {
            i += 1;
            try writer.print("[]", .{});
        } else {
            unreachable;
        }
    }
    try writer.print(")", .{});
}

fn argumentsCount(descriptor: []const u8) usize {
    var i: usize = 1;
    var count: usize = 0;
    while (i < descriptor.len and descriptor[i] != ')') {
        if (getSimpleType(descriptor[i])) |_| {
            i += 1;
            count += 1;
        } else if (descriptor[i] == 'L') {
            while (descriptor[i] != ';') {
                i += 1;
            }
            count += 1;
            i += 1;
        } else {
            unreachable;
        }
    }

    return count;
}

fn printWithNamespace(writer: Writer, name: []const u8) !void {
    var i: usize = 0;
    var start = i;
    while (i < name.len) {
        if (name[i] == '/') {
            try writer.print("{s}.", .{
                name[start..i],
            });
            start = i + 1;
        }
        i += 1;
    }
    try writer.print("{s}", .{
        name[start..i],
    });
}

fn printExceptions(writer: Writer, cp: *ConstantPool, methodInfo: MethodInfo) !void {
    for (methodInfo.attributes.items) |attribute| {
        switch (attribute) {
            AttributeInfo.exceptions => |exceptions| {
                const len = exceptions.exception_index_table.items.len;
                if (len > 0) {
                    try writer.print(" throws ", .{});
                }

                for (exceptions.exception_index_table.items, 0..) |exception, i| {
                    const exception_string = readString(cp, exception);
                    try printWithNamespace(writer, exception_string);
                    if (i < len - 1) {
                        try writer.print(", ", .{});
                    }
                }
            },
            else => {},
        }
    }
}

fn printMethodExceptions(writer: Writer, cp: *ConstantPool, exceptions: ExceptionsAttribute) !void {
    const len = exceptions.exception_index_table.items.len;
    if (len > 0) {
        try writer.print(" throws ", .{});
    }

    for (exceptions.exception_index_table.items, 0..) |exception, i| {
        const exception_string = readString(cp, exception);
        try printWithNamespace(writer, exception_string);
        if (i < len - 1) {
            try writer.print(", ", .{});
        }
    }
}

fn printVerbose(writer: Writer, cf: ClassFile, file_data: FileData) !void {
    try printHeader(writer, cf, file_data);
    try printConstantPool(writer, cf);
    try writer.print("{{\n", .{});
    var i: usize = 0;
    for (cf.fields.items) |field| {
        if (i > 0) {
            try writer.print("\n", .{});
        }
        try printField(writer, field);
        i += 1;
    }
    for (cf.methods.items) |method| {
        if (i > 0) {
            try writer.print("\n", .{});
        }
        try printMethod(writer, cf, method);
        try printMethodDetailed(writer, cf, method);
        i += 1;
    }
    try writer.print("}}\n", .{});
    try printFooter(writer, cf);
}

fn findSignature(attr: std.ArrayList(attributes.AttributeInfo)) ?attributes.SignatureAttribute {
    for (attr.items) |attribute| {
        switch (attribute) {
            .signature => |signature| return signature,
            else => {},
        }
    }
    return null;
}

fn printField(writer: Writer, field: FieldInfo) !void {
    var iter = field.access_flags.iter();
    try writer.print("  ", .{});
    while (iter.next()) |access_flag| {
        try writer.print("{s} ", .{access_flag.keyword()});
    }

    const descriptor = field.getDescriptor().bytes;

    try printNormalizedType(writer, descriptor);

    try writer.print(" {s};\n", .{
        field.getName().bytes,
    });

    try writer.print("    descriptor: {s}\n", .{
        descriptor,
    });

    // this one is lower case hedagits for some reason
    try writer.print("    flags: (0x{x:0>4}) ", .{
        field.access_flags.value,
    });

    iter = field.access_flags.iter();
    var i: usize = 0;
    while (iter.next()) |access_flag| {
        try writer.print("{s}", .{access_flag.name()});
        i += 1;
        if (i < field.access_flags.count()) {
            try writer.print(", ", .{});
        }
    }
    try writer.print("\n", .{});

    for (field.attributes.items) |attribute| {
        switch (attribute) {
            .constant_value => |constant_value| {
                try writer.print("    ConstantValue: ", .{});
                const constant = constant_value.constant_pool.get(constant_value.constantvalue_index);
                switch (constant) {
                    .long => |long| {
                        try writer.print("long {}l", .{long.bytes});
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
}

fn printSimpleType(writer: Writer, jtype: u8) !void {
    const str = getSimpleType(jtype);
    if (str) |s| {
        try writer.print("{s}", .{s});
    } else {
        std.debug.print("{c}\n", .{jtype});
        unreachable;
    }
}

fn getSimpleType(jtype: u8) ?[]const u8 {
    if (jtype == 'B') {
        return "byte";
    } else if (jtype == 'C') {
        return "char";
    } else if (jtype == 'D') {
        return "double";
    } else if (jtype == 'F') {
        return "float";
    } else if (jtype == 'I') {
        return "int";
    } else if (jtype == 'J') {
        return "long";
    } else if (jtype == 'S') {
        return "short";
    } else if (jtype == 'Z') {
        return "boolean";
    } else if (jtype == 'V') {
        return "void";
    } else {
        return null;
    }
}

fn printNormalizedType(writer: Writer, descriptor: []const u8) !void {
    if (descriptor.len == 1) {
        try printSimpleType(writer, descriptor[0]);
    } else {
        if (descriptor[0] == 'L') {
            var i: usize = 1;
            var start: usize = i;

            while (descriptor[i] != ';') {
                if (descriptor[i] == '/') {
                    try writer.print("{s}.", .{
                        descriptor[start..i],
                    });
                    i += 1;
                    start = i;
                } else {
                    i += 1;
                }
            }
            try writer.print("{s}", .{
                descriptor[start..i],
            });
        } else {
            unreachable;
        }
    }
}

fn printMethodDetailed(writer: Writer, cf: ClassFile, method: MethodInfo) !void {
    try writer.print("    descriptor: {s}\n", .{method.getDescriptor().bytes});
    try writer.print("    flags: (0x{X:0>4}) ", .{
        method.access_flags.value,
    });

    var iter = method.access_flags.iter();
    var i: usize = 0;
    while (iter.next()) |flag| {
        try writer.print("{s}", .{flag.name()});
        i += 1;
        if (i < method.access_flags.count()) {
            try writer.print(", ", .{});
        }
    }
    try writer.print("\n", .{});

    for (method.attributes.items) |attribute| {
        switch (attribute) {
            .code => |code| {
                var args_size = argumentsCount(method.getDescriptor().bytes);
                if (!method.access_flags.flags.static) {
                    args_size += 1;
                }

                try writer.print("    Code:\n      stack={}, locals={}, args_size={}\n", .{
                    code.max_stack,
                    code.max_locals,
                    args_size,
                });

                try printMethodCode(writer, code, cf);

                for (code.attributes.items) |method_attribute| {
                    switch (method_attribute) {
                        .line_number_table => |line_number_table_attribute| {
                            try writer.print("      LineNumberTable:\n", .{});
                            for (line_number_table_attribute.line_number_table.items) |line_number_entry| {
                                try writer.print("        line {}: {}\n", .{
                                    line_number_entry.line_number,
                                    line_number_entry.start_pc,
                                });
                            }
                        },
                        .local_variable_table => |local_variable_table| {
                            try writer.print("      LocalVariableTable:\n", .{});
                            try writer.print("        Start  Length  Slot  Name   Signature\n", .{});
                            for (local_variable_table.variables) |local_variable| {
                                try writer.print("         {: >4}  {: >6}  {: >4}  {s: >4}   {s}\n", .{
                                    local_variable.start_pc,
                                    local_variable.length,
                                    local_variable.index,
                                    cf.constant_pool.get(local_variable.name_index).utf8.bytes,
                                    cf.constant_pool.get(local_variable.descriptor_index).utf8.bytes,
                                });
                            }
                        },
                        else => |other| {
                            std.debug.print("local variable {any}", .{other});
                            unreachable;
                        },
                    }
                }
            },
            .exceptions => |exceptions| {
                try writer.print("    Exceptions:\n     ", .{});
                try printMethodExceptions(writer, cf.constant_pool, exceptions);
                try writer.print("\n", .{});
            },
            .method_parameters => |method_parameters| {
                try writer.print("    MethodParameters:\n", .{});
                try writer.print("      {s: <30} {s}\n", .{ "Name", "Flags" });
                for (method_parameters.parameters.items) |parameter| {
                    try writer.print("      {s: <30}", .{
                        parameter.name(cf.constant_pool),
                    });

                    var aiter = parameter.access_flags.iter();

                    while (aiter.next()) |a| {
                        try writer.print(" {s}", .{a.name()});
                    }
                    try writer.print("\n", .{});
                }
            },
            .signature => |signature| {
                try writer.print("    ", .{});
                try printSignature(writer, signature);
            },
            else => |other| {
                std.debug.print("{any}", .{other});
                unreachable;
            },
        }
    }
}

fn printSignature(writer: Writer, signature: attributes.SignatureAttribute) !void {
    try writer.print("Signature: #{: <27} // {s}\n", .{
        signature.signature_index,
        signature.constant_pool.get(signature.signature_index).utf8.bytes,
    });
}

pub const OpType = enum {
    bi_push_params,
    si_push_params,
    ldc,
    constant_pool_ref,
    local_index_operation,
    iinc,
    branch,
    branch_wide,
    empty,
};

pub const OperationType = union(OpType) {
    bi_push_params: ops.BipushParams,
    si_push_params: ops.SipushParams,
    ldc: u8,
    constant_pool_ref: ops.ConstantPoolRefOperation,
    local_index_operation: ops.LocalIndexOperation,
    iinc: ops.IincParams,
    branch: ops.BranchToOffsetOperation,
    branch_wide: ops.BranchToOffsetWideOperation,
    empty: u0,

    pub fn fromOperation(op: Operation) OperationType {
        switch (op) {
            .bipush => |bipush| {
                return OperationType{ .bi_push_params = bipush };
            },
            .sipush => |sipush| {
                return OperationType{ .si_push_params = sipush };
            },
            .ldc => |ldc| {
                return OperationType{ .ldc = ldc };
            },
            .ldc_w,
            .ldc2_w,
            .getstatic,
            .putstatic,
            .getfield,
            .putfield,
            .invokevirtual,
            .invokespecial,
            .invokestatic,
            .new,
            .anewarray,
            .checkcast,
            .instanceof,
            => |constant_pool_ref| {
                return OperationType{ .constant_pool_ref = constant_pool_ref };
            },
            .iload,
            .lload,
            .fload,
            .dload,
            .aload,
            .istore,
            .lstore,
            .fstore,
            .dstore,
            .astore,
            => |local_index_operation| {
                return OperationType{ .local_index_operation = local_index_operation };
            },
            .iinc => |iinc| {
                return OperationType{ .iinc = iinc };
            },
            .ifeq,
            .ifne,
            .iflt,
            .ifge,
            .ifgt,
            .ifle,
            .if_icmpeq,
            .if_icmpne,
            .if_icmplt,
            .if_icmpge,
            .if_icmpgt,
            .if_icmple,
            .if_acmpeq,
            .if_acmpne,
            .goto,
            .jsr,
            .ifnull,
            .ifnonnull,
            => |branch| {
                return OperationType{ .branch = branch };
            },
            .goto_w,
            .jsr_w,
            => |branch_wide| {
                return OperationType{ .branch_wide = branch_wide };
            },
            .tableswitch => unreachable,
            .lookupswitch => unreachable,
            .invokeinterface => unreachable,
            .invokedynamic => unreachable,
            .newarray => unreachable,
            .multianewarray => unreachable,
            else => return OperationType{ .empty = 0 },
        }
    }
};

fn printMethodCode(writer: Writer, code_attribute: CodeAttribute, cf: ClassFile) !void {
    var fbs = std.io.fixedBufferStream(code_attribute.code.items);
    const reader = fbs.reader();

    const allocator = std.heap.page_allocator;
    var offset: usize = 0;
    while (true) {
        const op = Operation.decode(allocator, reader) catch |err| {
            if (err == error.EndOfStream) {
                break;
            } else {
                return err;
            }
        };

        const operationType = OperationType.fromOperation(op);

        switch (operationType) {
            .empty => {
                try writer.print("{: >10}: {s}", .{
                    offset,
                    @tagName(op),
                });
            },
            else => {
                try writer.print("{: >10}: {s: <14}", .{
                    offset,
                    @tagName(op),
                });
            },
        }

        offset += op.sizeOf();

        switch (operationType) {
            .ldc => |constant| {
                try writer.print("#{: <18} // ", .{
                    constant,
                });

                try printDetailed(
                    writer,
                    cf,
                    cf.constant_pool.get(constant),
                );
            },
            .bi_push_params => |bi_push_params| {
                try writer.print("#{}", .{
                    bi_push_params,
                });
            },
            .local_index_operation => |local_index| {
                try writer.print("#{}", .{
                    local_index,
                });
            },
            .constant_pool_ref => |pool_ref| {
                try writer.print("#{: <18} // ", .{
                    pool_ref,
                });

                try printDetailed(
                    writer,
                    cf,
                    cf.constant_pool.get(pool_ref),
                );
            },
            else => {},
        }

        try writer.print("\n", .{});
    }
}

fn printDetailed(writer: Writer, cf: ClassFile, constant: Entry) !void {
    switch (constant) {
        .fieldref => |fieldref| {
            try writer.print("Field ", .{});

            if (fieldref.class_index != cf.this_class) {
                const class_info = fieldref.constant_pool.get(fieldref.class_index).class;
                try writer.print("{s}.", .{class_info.getName().bytes});
            }

            try printDetailed(
                writer,
                cf,
                fieldref.constant_pool.get(fieldref.name_and_type_index),
            );
        },
        .methodref => |methodref| {
            try writer.print("Method ", .{});
            if (methodref.class_index != cf.this_class) {
                const class_info = methodref.constant_pool.get(methodref.class_index).class;
                try writer.print("{s}.", .{class_info.getName().bytes});
            }

            try printDetailed(
                writer,
                cf,
                methodref.constant_pool.get(methodref.name_and_type_index),
            );
        },
        .class => |class_info| {
            try writer.print("class {s}", .{class_info.getName().bytes});
        },
        .name_and_type => |name_and_type| {
            try writer.print("{s}:{s}", .{
                escape(name_and_type.getName().bytes),
                name_and_type.getDescriptor().bytes,
            });
        },
        .string => |string| {
            try writer.print("String {s}", .{
                cf.constant_pool.get(string.string_index).utf8.bytes,
            });
        },
        .integer => |integer| {
            try writer.print("int {d}", .{
                integer.bytes,
            });
        },
        else => {
            std.debug.print("{any}", .{constant});
            unreachable;
        },
    }
}

pub fn printSha256sum(writer: Writer, data: []const u8) !void {
    var hash: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    hasher.final(&hash);
    for (hash) |h| {
        try writer.print("{x:0>2}", .{h});
    }
    try writer.print("\n", .{});
}

fn printHeader(writer: Writer, cf: ClassFile, file_data: FileData) !void {
    try writer.print("Classfile {s}\n", .{file_data.path});
    try writer.print("  Last modified {s}; size {d} bytes\n", .{
        "date",
        file_data.data.len,
    });

    try writer.print("  SHA-256 checksum ", .{});
    try printSha256sum(writer, file_data.data);

    if (findSourceFile(cf)) |source_file| {
        try writer.print("  Compiled from \"{s}\"\n", .{source_file});
    }
    var iter = cf.access_flags.iter();
    while (iter.next()) |flag| {
        if (flag != .super) {
            try writer.print("{s} ", .{@tagName(flag)});
        }
    }
    try writer.print("class ", .{});
    const className = readString(cf.constant_pool, cf.this_class);
    try printEscapedSignature(writer, className);

    if (findSignature(cf.attributes)) |signatureAttribute| {
        const signature = readString(cf.constant_pool, signatureAttribute.signature_index);
        try writer.print(" extends ", .{});
        try printEscapedSignature(writer, signature);
        try writer.print("\n", .{});
    } else if (cf.super_class) |super_class| {
        const superClass = readString(cf.constant_pool, super_class);
        try writer.print(" extends \n", .{});
        try printEscapedSignature(writer, superClass);
        try writer.print("\n", .{});
    }
    try writer.print("  minor version: {}\n", .{cf.minor_version});
    try writer.print("  major version: {}\n", .{cf.major_version});
    try writer.print("  flags: (0x{X:0>4}) ", .{cf.access_flags.value});

    var flags_iter = cf.access_flags.iter();
    while (flags_iter.next()) |flag| {
        if (flags_iter.index > 1) {
            try writer.print(", ", .{});
        }
        try writer.print("{s}", .{flag.name()});
    }

    try writer.print("\n", .{});
    try writer.print("  this_class: #{: <27}// {s}\n", .{
        cf.this_class,
        readString(cf.constant_pool, cf.this_class),
    });
    if (cf.super_class) |super_class| {
        try writer.print("  super_class: #{: <26}// {s}\n", .{
            super_class,
            readString(cf.constant_pool, super_class),
        });
    }
    try writer.print("  interfaces: {}, fields: {}, methods: {}, attributes: {}\n", .{
        cf.interfaces.items.len,
        cf.fields.items.len,
        cf.methods.items.len,
        cf.attributes.items.len,
    });
}

fn printEscapedSignature(writer: Writer, signature: []u8) !void {
    var i: usize = 0;
    var start = i;
    while (i < signature.len) {
        if (signature[i] == '/' or signature[i] == ';' or signature[i] == 'L') {
            if (signature[i] == 'L' and start == i) {
                start = i + 1;
            } else {
                try writer.print("{s}", .{
                    signature[start..i],
                });
                if (signature[i] == '/') {
                    try writer.print(".", .{});
                }
                start = i + 1;
            }
        }
        i += 1;
    }
    try writer.print("{s}", .{
        signature[start..i],
    });
}

fn findSourceFile(cf: ClassFile) ?[]const u8 {
    var file: ?[]const u8 = null;

    for (cf.attributes.items) |attribute| {
        switch (attribute) {
            .source_file => |source_file| {
                file = readString(cf.constant_pool, source_file.source_file_index);
            },
            else => {},
        }
    }

    return file;
}

fn printFooter(writer: Writer, cf: ClassFile) !void {
    for (cf.attributes.items) |attribute| {
        switch (attribute) {
            .source_file => |source_file| {
                const index = source_file.source_file_index;
                const name = readString(cf.constant_pool, index);
                try writer.print("SourceFile: \"{s}\"\n", .{name});
            },
            .runtime_visible_annotations => |runtime_visible_annotations| {
                for (runtime_visible_annotations.annotations, 0..) |annotation, i| {
                    try writer.print("RuntimeVisibleAnnotations:\n", .{});
                    try writer.print("  {d}: #{d}(", .{
                        i,
                        annotation.type_index,
                    });

                    for (annotation.element_value_pairs, 0..) |pair, j| {
                        if (j > 1) try writer.print(", ", .{});
                        try writer.print("#{d}=", .{
                            pair.element_name_index,
                        });
                        switch (pair.value) {
                            .String => |string| try writer.print("s#{d}", .{string}),
                            else => unreachable,
                        }
                    }

                    try writer.print(")\n", .{});
                    const type_name = readString(cf.constant_pool, annotation.type_index);
                    try writer.print("    ", .{});
                    try printWithNamespace(writer, type_name[1 .. type_name.len - 1]);
                    try writer.print("(\n", .{});

                    for (annotation.element_value_pairs) |pair| {
                        try writer.print("      {s}=", .{
                            readString(cf.constant_pool, pair.element_name_index),
                        });
                        switch (pair.value) {
                            .String => |string| {
                                try writer.print("\"", .{});
                                try print_string(writer, readString(cf.constant_pool, string));
                                try writer.print("\"", .{});
                            },
                            else => unreachable,
                        }
                        try writer.print("\n", .{});
                    }

                    try writer.print("    )\n", .{});
                }
            },
            .unknown => |unknown| {
                try writer.print("  {s}: length = 0x{X} (unknown attribute)\n", .{
                    unknown.unknown_name,
                    unknown.data.len,
                });
                var i: usize = 0;
                for (unknown.data) |byte| {
                    if (i > 0 and i % 16 == 0) {
                        try writer.print("\n  ", .{});
                    } else if (i % 16 == 0) {
                        try writer.print("  ", .{});
                    }
                    try writer.print(" {X:0>2}", .{byte});
                    i += 1;
                }
                try writer.print("\n", .{});
            },
            .signature => |signature| try printSignature(writer, signature),
            .inner_classes => |inner_classes| {
                try writer.print("InnerClasses:\n", .{});
                for (inner_classes.inner_classes) |inner_class| {
                    var iter = inner_class.inner_class_access_flags.iter();
                    try writer.print("  ", .{});
                    while (iter.next()) |flag| {
                        try writer.print("{s} ", .{flag.keyword()});
                    }

                    try writer.print("#{d};", .{
                        inner_class.inner_class_info_index,
                    });

                    const count = 25 - intAsStringLength(inner_class.inner_class_info_index);

                    for (count) |_| {
                        try writer.print(" ", .{});
                    }

                    const class_index = inner_class.inner_class_info_index;
                    const class = cf.constant_pool.get(class_index).class;
                    try writer.print("// class {s}\n", .{
                        class.getName().bytes,
                    });
                }
            },
            else => unreachable,
        }
    }
}

fn intAsStringLength(number: u16) usize {
    var count: usize = 0;
    var rest = number;
    while (rest > 0) {
        rest = rest / 10;
        count += 1;
    }
    return count;
}

fn printConstantPool(writer: Writer, cf: ClassFile) !void {
    try writer.print("Constant pool:\n", .{});
    var buffer: [100]u8 = undefined;
    var i: usize = 0;
    while (i < cf.constant_pool.entries.items.len) {
        const constant = cf.constant_pool.entries.items[i];
        const is = try std.fmt.bufPrint(buffer[0..], "#{}", .{i + 1});
        try writer.print("{s:5} = ", .{is});
        switch (constant) {
            .class => |class| {
                const name = "Class";
                const number = try std.fmt.bufPrint(buffer[0..], "#{}", .{class.name_index});
                try writer.print("{s: <18} {s: <14} // {s}\n", .{
                    name,
                    number,
                    class.getName().bytes,
                });
            },
            .name_and_type => |name_and_type| {
                const name = "NameAndType";
                const number = try std.fmt.bufPrint(buffer[0..], "#{}:#{}", .{
                    name_and_type.name_index,
                    name_and_type.descriptor_index,
                });
                const method_name = escape(name_and_type.getName().bytes);
                const descriptor = name_and_type.getDescriptor().bytes;
                try writer.print("{s: <18} {s: <14} // {s}:{s}\n", .{
                    name,
                    number,
                    method_name,
                    descriptor,
                });
            },
            .utf8 => |utf8| {
                const name = "Utf8";
                try writer.print("{s: <18} ", .{
                    name,
                });
                try print_string(writer, utf8.bytes);
                try writer.print("\n", .{});
            },
            .string => |string| {
                const string_value = readString(cf.constant_pool, string.string_index);
                const name = "String";
                const number = try std.fmt.bufPrint(buffer[0..], "#{}", .{string.string_index});
                try writer.print("{s: <18} {s: <14} // {s}\n", .{
                    name,
                    number,
                    string_value,
                });
            },
            .methodref => |method| {
                try printRef(writer, "Methodref", method);
            },
            .fieldref => |fieldref| {
                try printRef(writer, "Fieldref", fieldref);
            },
            .long => |long| {
                const name = "Long";
                try writer.print("{s: <18} {d}l\n", .{
                    name,
                    long.bytes,
                });
                i += 1;
            },
            .integer => |integer| {
                const name = "Integer";
                try writer.print("{s: <18} {d}\n", .{ name, integer.bytes });
            },
            else => |other| {
                std.debug.print(": {any}", .{other});
                unreachable;
            },
        }
        i += 1;
    }
}

fn print_string(writer: Writer, string: []const u8) !void {
    var i: usize = 0;
    while (i < string.len) {
        const byte = string[i];
        switch (byte) {
            '\t' => try writer.print("\\t", .{}),
            '\n' => try writer.print("\\n", .{}),
            '\r' => try writer.print("\\r", .{}),
            8 => try writer.print("\\b", .{}),
            12 => try writer.print("\\f", .{}),
            '"' => try writer.print("\\\"", .{}),
            '\'' => try writer.print("\\'", .{}),
            '\\' => try writer.print("\\\\", .{}),
            else => {
                if (byte >= 32 and byte < 127) {
                    try writer.print("{c}", .{byte});
                } else {
                    try writer.print("\\u00{x:0>2}", .{byte});
                }
            },
        }
        i += 1;
    }
}

fn printRef(writer: Writer, name: []const u8, ref: RefInfo) !void {
    var buffer: [100]u8 = undefined;

    const number = try std.fmt.bufPrint(buffer[0..], "#{}.#{}", .{
        ref.class_index,
        ref.name_and_type_index,
    });
    try writer.print("{s: <18} {s: <14} ", .{
        name,
        number,
    });
    const class_name = ref.getClassInfo().getName().bytes;
    const name_and_type = ref.getNameAndTypeInfo();
    const method_name = escape(name_and_type.getName().bytes);
    const descriptor = name_and_type.getDescriptor().bytes;
    try writer.print("// {s}.{s}:{s}\n", .{
        class_name,
        method_name,
        descriptor,
    });
}

fn escape(name: []u8) []const u8 {
    if (std.mem.eql(u8, name, "<init>")) {
        return "\"<init>\"";
    } else {
        return name;
    }
}

test "getRetunType returns last element" {
    const result = getReturnType("([Ljava/lang/String;)V");
    try std.testing.expect(std.mem.eql(u8, result, "V"));
}

test "argumentsCount works with simple types" {
    try std.testing.expectEqual(
        1,
        argumentsCount("(I)L/java/lang/Object;"),
    );
}
