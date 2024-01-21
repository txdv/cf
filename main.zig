const std = @import("std");
const MethodInfo = @import("src/MethodInfo.zig");
const ClassFile = @import("src/ClassFile.zig");
const ConstantPool = @import("src/ConstantPool.zig");
const Entry = ConstantPool.Entry;
const AttributeInfo = @import("src/attributes.zig").AttributeInfo;
const Writer = std.io.BufferedWriter(4096, std.fs.File.Writer).Writer;

const Allocator = std.mem.Allocator;

pub fn readFile(allocator: std.mem.Allocator, filename: []u8) ![]u8 {
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const path = try std.fs.realpath(filename, &path_buffer);

    const file = try std.fs.openFileAbsolute(path, .{});

    const bytes = try file.readToEndAlloc(allocator, 4096);
    return bytes;
}

pub fn main() !void {
    const out = std.io.getStdOut().writer();
    var buf = std.io.bufferedWriter(out);
    var w = buf.writer();

    if (std.os.argv.len < 2) {
        try w.print("Specify a file\n", .{});

        unreachable;
        //return error.FileNotFound;
    }
    const filename = std.os.argv[1];
    const filename_length = std.mem.len(filename);
    const allocator = std.heap.page_allocator;
    const data = try readFile(allocator, filename[0..filename_length]);
    defer allocator.free(data);

    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();

    var cf = try ClassFile.decode(allocator, reader);
    defer cf.deinit();

    try printSimple(cf, w);
    try buf.flush();
}

fn printSimple(cf: ClassFile, writer: Writer) !void {
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
                        try writer.print("Compiled from \"{s}\"\n", .{utf8.bytes});
                    },
                    else => unreachable,
                }
            },
            else => {},
        }
    }
}

fn readString(cp: *ConstantPool, index: u16) []u8 {
    const entry = cp.entries.items[index];
    switch (entry) {
        Entry.utf8 => |utf8| {
            return utf8.bytes;
        },
        else => unreachable,
    }
}

fn printClass(writer: Writer, cf: ClassFile) !void {
    const className = readString(cf.constant_pool, cf.this_class);
    try writer.print("public class {s} {{\n", .{className});
    for (cf.methods.items) |method| {
        var name = method.getName().bytes;
        const is_constructor = std.mem.eql(u8, name, "<init>");
        if (is_constructor) {
            name = className;
        }
        try printModifiers(writer, method);
        const descriptor = method.getDescriptor().bytes;
        if (!is_constructor)
            try printReturnType(writer, descriptor);
        try writer.print("{s}", .{name});
        try printArguments(writer, descriptor);
        try printExceptions(writer, cf.constant_pool, method);
        try writer.print(";\n", .{});
    }
    try writer.print("}}\n", .{});
}

fn printModifiers(writer: Writer, method: MethodInfo) !void {
    try writer.print("  ", .{});
    if (method.access_flags.public) {
        try writer.print("public ", .{});
    }
    if (method.access_flags.private) {
        try writer.print("private ", .{});
    }
    if (method.access_flags.protected) {
        try writer.print("protected ", .{});
    }
    if (method.access_flags.static) {
        try writer.print("static ", .{});
    }
    if (method.access_flags.final) {
        try writer.print("final ", .{});
    }
}

fn getReturnType(descriptor: []const u8) []const u8 {
    var i = descriptor.len - 1;
    while (descriptor[i] != ')') {
        i -= 1;
    }
    return descriptor[i + 1 .. descriptor.len];
}

fn printReturnType(writer: Writer, descriptor: []const u8) !void {
    const return_type = getReturnType(descriptor);
    if (return_type.len == 1) {
        if (return_type[0] == 'V') {
            try writer.print("void ", .{});
        }
    }
}

fn printArguments(writer: Writer, descriptor: []const u8) !void {
    try writer.print("(", .{});
    var i: usize = descriptor.len - 2;
    while (i > 0 and descriptor[i] != '(') {
        if (descriptor[i] == ';') {
            const end = i;
            while (descriptor[i] != 'L') {
                i -= 1;
            }
            const start = i + 1;
            const name = descriptor[start..end];
            try printWithNamespace(writer, name);
        } else if (descriptor[i] == '[') {
            try writer.print("[]", .{});
        }
        i -= 1;
    }
    try writer.print(")", .{});
}

fn printWithNamespace(writer: Writer, name: []const u8) !void {
    var i: usize = 0;
    var start = i;
    while (i < name.len) {
        if (name[i] == '/') {
            try writer.print("{s}.", .{name[start..i]});
            start = i + 1;
        }
        i += 1;
    }
    try writer.print("{s}", .{name[start..i]});
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

test "getRetunType returns last element" {
    const result = getReturnType("([Ljava/lang/String;)V");
    try std.testing.expect(std.mem.eql(u8, result, "V"));
}
