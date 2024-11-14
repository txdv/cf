const std = @import("std");
const ClassFile = @import("src/ClassFile.zig");
const ConstantPool = @import("src/ConstantPool.zig");
const attributes = @import("src/attributes.zig");
const AttributeInfo = attributes.AttributeInfo;
const Annotation = attributes.Annotation;
const RuntimeVisibleAnnotationsAttribute = attributes.RuntimeVisibleAnnotationsAttribute;

const Utils = @import("Utils.zig");
const FileData = Utils.FileData;

fn findScalaSig(cf: *ClassFile) ?[]u8 {
    for (cf.attributes.items) |attribute| {
        switch (attribute) {
            AttributeInfo.runtime_visible_annotations => |runtime_annotation| {
                for (runtime_annotation.annotations) |annotation| {
                    const type_name = readString(cf.constant_pool, annotation.type_index);

                    if (type_name) |tn| {
                        if (std.mem.eql(u8, tn, "Lscala/reflect/ScalaSignature;")) {
                            for (annotation.element_value_pairs) |pair| {
                                const element_name_opt = readString(cf.constant_pool, pair.element_name_index);
                                if (element_name_opt) |element_name| {
                                    if (std.mem.eql(u8, element_name, "bytes")) {
                                        switch (pair.value) {
                                            .String => |string| {
                                                return readString(cf.constant_pool, string);
                                            },
                                            else => {},
                                        }
                                    }
                                    return null;
                                } else {
                                    return null;
                                }
                            }
                            return null;
                        } else {
                            return null;
                        }
                    } else {
                        return null;
                    }
                }
            },
            else => {},
        }
    }

    return null;
}

fn readString(cp: *ConstantPool, index: u16) ?[]u8 {
    const entry = cp.get(index);
    return switch (entry) {
        .utf8 => |utf8| utf8.bytes,
        .class => |class| readString(cp, class.name_index),
        else => null,
    };
}

fn regenerateZero(src: []u8) usize {
    var i: usize = 0;
    var j: usize = 0;
    const srclen = src.len;

    while (i < srclen) {
        const input = src[i] & 0xff;
        if (input == 0xc0 and (i + 1 < srclen) and (src[i + 1] & 0xff == 0x80)) {
            src[j] = 0x7f;
            i += 2;
        } else if (input == 0) {
            src[j] = 0x7f;
            i += 1;
        } else {
            src[j] = (input - 1);
            i += 1;
        }
        j += 1;
    }
    return j;
}

fn decode7to8(src: []u8, srclen: usize) usize {
    var i: usize = 0;
    var j: usize = 0;
    const dstlen = (srclen * 7 + 7) / 8;

    while (i + 7 < srclen) {
        var out: u8 = src[i];
        var in: u8 = src[i + 1];
        src[j] = out | ((in & 0x01) << 7);
        out = in >> 1;
        in = src[i + 2];
        src[j + 1] = out | ((in & 0x03) << 6);
        out = in >> 2;
        in = src[i + 3];
        src[j + 2] = out | ((in & 0x07) << 5);
        out = in >> 3;
        in = src[i + 4];
        src[j + 3] = out | ((in & 0x0f) << 4);
        out = in >> 4;
        in = src[i + 5];
        src[j + 4] = out | ((in & 0x1f) << 3);
        out = in >> 5;
        in = src[i + 6];
        src[j + 5] = out | ((in & 0x3f) << 2);
        out = in >> 6;
        in = src[i + 7];
        src[j + 6] = out | (in << 1);

        i += 8;
        j += 7;
    }

    if (i < srclen) {
        var out: u8 = src[i];
        if (i + 1 < srclen) {
            var in: u8 = src[i + 1];
            src[j] = out | ((in & 0x01) << 7);
            j += 1;
            out = in >> 1;
            if (i + 2 < srclen) {
                in = src[i + 2];
                src[j] = out | ((in & 0x03) << 6);
                j += 1;
                out = in >> 2;
                if (i + 3 < srclen) {
                    in = src[i + 3];
                    src[j] = out | ((in & 0x07) << 5);
                    j += 1;
                    out = in >> 3;
                    if (i + 4 < srclen) {
                        in = src[i + 4];
                        src[j] = out | ((in & 0x0f) << 4);
                        j += 1;
                        out = in >> 4;
                        if (i + 5 < srclen) {
                            in = src[i + 5];
                            src[j] = out | ((in & 0x1f) << 3);
                            j += 1;
                            out = in >> 5;
                            if (i + 6 < srclen) {
                                in = src[i + 6];
                                src[j] = out | ((in & 0x3f) << 2);
                                j += 1;
                                out = in >> 6;
                            }
                        }
                    }
                }
            }
        }
        if (j < dstlen) src[j] = out;
    }

    return dstlen;
}

fn readVarInt32(reader: anytype) !i32 {
    var result: i32 = 0;
    var shift: u5 = 0;

    while (true) {
        const b: u8 = try reader.readByte();
        result |= (@as(i32, b) & 0x7f) << shift;
        if ((b & 0x80) != 0x80) break;
        shift += 7;
    }

    return result;
}

fn readVar(comptime t: anytype, reader: anytype) !t {
    var result: t = 0;

    while (true) {
        const b: u8 = try reader.readByte();
        result |= (@as(u32, b) & 0x7f);
        if ((b & 0x80) != 0x80) break;
        result = result << 7;
    }

    return result;
}

pub fn main() !void {
    const filename = Utils.getFilename();

    const allocator = std.heap.page_allocator;
    var file_data: FileData = undefined;
    try Utils.readFileData(allocator, filename, &file_data);
    defer file_data.free(allocator);

    var stream = std.io.fixedBufferStream(file_data.data);
    const reader = stream.reader();

    var cf = try ClassFile.decode(allocator, reader);
    defer cf.deinit();

    if (findScalaSig(&cf)) |scalaSig| {
        try Utils.printHex(scalaSig);

        const len = regenerateZero(scalaSig);

        const new_len = decode7to8(scalaSig, len);

        const newSlice = scalaSig[0..new_len];

        try Utils.printHex(newSlice);
        const table = try SymbolTable.read(newSlice, allocator);

        table.debug();

        std.debug.print("\n", .{});
        for (table.headers, 0..) |header, i| {
            const header_data = header.dataSlice(newSlice);

            std.debug.print("{d:>4}. ", .{i});

            const h = try SymbolHeader.read(header, &table, header_data);

            h.debug(&table);
        }
    }
}

fn debug(debuggable: anytype, table: *const SymbolTable) void {
    debuggable.debug(table);
}

fn generic_debug(obj: anytype, table: *const SymbolTable) void {
    _ = table;
    std.debug.print("{}\n", .{obj});
}

// symbol:
// - NoSymbol
// - TypeSymbol
// - AliasSymbol
// - ClassSymbol
// - ObjectSymbol
// - MethodSymbol
// - ExtRef
// - ExtModClassRef

const MethodType = struct {
    result_type: u32,
    param_symbols: []u8,

    fn read(data: []u8) !MethodType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return MethodType{
            .result_type = try readVar(u32, reader),
            .param_symbols = data[try stream.getPos()..],
        };
    }

    fn debug(self: MethodType, table: *const SymbolTable) void {
        generic_debug(self, table);
    }
};

const ClassInfoType = struct {
    symbol: u32,
    type_refs: []u8,

    fn read(data: []u8) !ClassInfoType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return ClassInfoType{
            .symbol = try readVar(u32, reader),
            .type_refs = data[try stream.getPos()..],
        };
    }

    fn debug(self: ClassInfoType, table: *const SymbolTable) void {
        generic_debug(self, table);
    }
};

const ThisType = struct {
    symbol: u32,

    fn read(data: []u8) !ThisType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        return ThisType{
            .symbol = try readVar(u32, reader),
        };
    }

    fn debug(self: ThisType, table: *const SymbolTable) void {
        _ = table;
        //const name = table.headers[self.symbol];
        std.debug.print("ThisType {{ .symbol = {} }}\n", .{
            self.symbol,
        });
    }
};

const ExtRef = struct {
    name: u32,
    symbol: ?u32,

    fn read(data: []u8) !ExtRef {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return ExtRef{
            .name = try readVar(u32, reader),
            .symbol = readVar(u32, reader) catch null,
        };
    }

    pub fn debug(self: ExtRef, table: *const SymbolTable) void {
        std.debug.print("ExtRef {{ .name = {s}, .symbol = {any} }}\n", .{
            table.getName(self.name),
            self.symbol,
        });
    }
};

const ExtModClassRef = struct {
    name: u32,
    symbol: ?u32,

    fn read(data: []u8) !ExtModClassRef {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return ExtModClassRef{
            .name = try readVar(u32, reader),
            .symbol = readVar(u32, reader) catch null,
        };
    }

    pub fn debug(self: ExtModClassRef, table: *const SymbolTable) void {
        std.debug.print("ExtModClassRef {{ .name = {s}, .symbol = {any} }}\n", .{
            table.getName(self.name),
            self.symbol,
        });
    }
};

const TypeRefType = struct {
    type_ref: u32,
    symbol_ref: u32,
    type_args: []u8,

    fn read(data: []u8) !TypeRefType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return TypeRefType{
            .type_ref = try readVar(u32, reader),
            .symbol_ref = try readVar(u32, reader),
            .type_args = data[try stream.getPos()..],
        };
    }

    fn debug(self: TypeRefType, table: *const SymbolTable) void {
        _ = table;

        std.debug.print("TypeRefType {{ .type_ref = {}, .symbol_ref = {}, .args = {} }}\n", .{
            self.type_ref,
            self.symbol_ref,
            self.type_args.len,
        });
    }
};

const SymbolInfo = struct {
    name: u32,
    symbol: u32,
    flags: u32,
    private_within: ?u32,
    info: u32,

    fn read(data: []u8) !SymbolInfo {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return try read2(reader);
    }

    fn read2(reader: anytype) !SymbolInfo {
        const name = try readVar(u32, reader);
        const symbol = try readVar(u32, reader);
        const flags = try readVar(u32, reader);
        const private_within = try readVar(u32, reader);
        const info = readVar(u32, reader) catch {
            return SymbolInfo{
                .name = name,
                .symbol = symbol,
                .flags = flags,
                .private_within = null,
                .info = private_within,
            };
        };
        return SymbolInfo{
            .name = name,
            .symbol = symbol,
            .flags = flags,
            .private_within = private_within,
            .info = info,
        };
    }

    pub fn debug(self: SymbolInfo, table: *const SymbolTable) void {
        const name = table.*.headers[self.name].dataSlice(table.*.data);
        std.debug.print("SymbolInfo {{ .name = {s}, .flags = {}, .info = {} }}\n", .{
            name,
            self.flags,
            self.info,
        });
    }
};

const HeaderType = enum(u8) {
    term_name = 1,
    type_name = 2,
    no_symbol = 3,
    type_symbol = 4,
    alias_symbol = 5,
    class_symbol = 6,
    object_symbol = 7,
    method_symbol = 8,
    ext_ref = 9,
    ext_mod_class_ref = 10,
    no_type = 11,
    no_prefix_type = 12,
    this_type = 13,
    single_type = 14,
    constant_type = 15,
    type_ref_type = 16,
    type_bounds_type = 17,
    refined_type = 18,
    class_info_type = 19,
    method_type = 20,
    poly_type = 21,
    //NullaryMethodType = 21, // overlapping?
    //method_type2 = 22,
    annotated_type = 42,
    annotated_with_self_type = 51,
    existential_type = 48,
};

const Header = union(HeaderType) {
    term_name: TermName,
    type_name: TypeName,
    no_symbol: NoSymbol,
    type_symbol: TypeSymbol,
    alias_symbol: AliasSymbol,
    class_symbol: ClassSymbol,
    object_symbol: ObjectSymbol,
    method_symbol: MethodSymbol,
    ext_ref: ExtRef,
    ext_mod_class_ref: ExtModClassRef,
    no_type: NoType,
    no_prefix_type: NoPrefixType,
    this_type: ThisType,
    single_type: SingleType,
    constant_type: ConstantType,
    type_ref_type: TypeRefType,
    type_bounds_type: TypeBoundsType,
    refined_type: RefinedType,
    class_info_type: ClassInfoType,
    method_type: MethodType,
    poly_type: PolyType,
    //NullaryMethodType = 21, // overlapping?
    //method_type2 = 22,
    annotated_type: AnnotatedType,
    annotated_with_self_type: AnnotatedWithSelfType,
    existential_type: ExistentialType,

    fn debug(header: Header, table: *const SymbolTable) void {
        _ = table;
        switch (header) {
            .term_name => |name| std.debug.print("TermName = \"{s}\"\n", .{name.name}),
            .type_name => |name| std.debug.print("Typenamee = \"{s}\"\n", .{name.name}),
            else => |item| std.debug.print("{}\n", .{item}),
        }
        //std.debug.print("{}\n", .{header});
    }
};

const TermName = struct {
    name: []u8,
};

const TypeName = struct {
    name: []u8,
};

const NoSymbol = struct {};

const TypeSymbol = struct {};

const AliasSymbol = struct {};

const ClassSymbol = struct {
    symbol: SymbolInfo,
    this_type_ref: ?u32,

    fn read(data: []u8) !ClassSymbol {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return .{
            .symbol = try SymbolInfo.read2(reader),
            .this_type_ref = readVar(u32, reader) catch null,
        };
    }
};

const ObjectSymbol = struct {
    symbol: SymbolInfo,
};

const MethodSymbol = struct {
    symbol: SymbolInfo,
    alias: ?u32,

    fn read(data: []u8) !MethodSymbol {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return MethodSymbol{
            .symbol = try SymbolInfo.read2(reader),
            .alias = readVar(u32, reader) catch null,
        };
    }
};

const NoType = struct {};

const NoPrefixType = struct {};

const SingleType = struct {
    type_ref: u32,
    symbol_ref: u32,

    fn read(data: []u8) !SingleType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        std.debug.print("data = {any}\n", .{data});

        return SingleType{
            .type_ref = try readVar(u32, reader),
            .symbol_ref = try readVar(u32, reader),
        };
    }
};

const ConstantType = struct {};

const TypeBoundsType = struct {};

const RefinedType = struct {};

const AnnotatedType = struct {};

const AnnotatedWithSelfType = struct {};

const ExistentialType = struct {};

const PolyType = struct {};

const SymbolHeader = struct {
    header_type: HeaderType,
    offset: u64,
    size: u32,
    header_size: u8,

    fn dataOffset(self: SymbolHeader) u64 {
        return self.offset + self.header_size;
    }

    fn dataSlice(self: SymbolHeader, data: []u8) []u8 {
        return data[self.dataOffset() .. self.dataOffset() + self.size];
    }

    fn read(self: SymbolHeader, table: *const SymbolTable, data: []u8) !Header {
        // const info = @typeInfo(Header).Union;
        //
        // inline for (info.fields) |field| {
        //     if (std.mem.eql(u8, field.name, @tagName(self.header_type))) {
        //         return field.type.read(table, data);
        //     }
        // }
        //
        // unreachable;

        _ = table;
        return switch (self.header_type) {
            .term_name => .{ .term_name = .{ .name = data } },
            .type_name => .{ .type_name = .{ .name = data } },
            .no_symbol => .{ .no_symbol = .{} },
            .type_ref_type => .{ .type_ref_type = try TypeRefType.read(data) },

            .class_symbol => .{ .class_symbol = try ClassSymbol.read(data) },
            .object_symbol => .{ .object_symbol = .{ .symbol = try SymbolInfo.read(data) } },
            .method_symbol => .{ .method_symbol = try MethodSymbol.read(data) },
            .ext_ref => .{ .ext_ref = try ExtRef.read(data) },

            .this_type => .{ .this_type = try ThisType.read(data) },
            .single_type => .{ .single_type = try SingleType.read(data) },

            .class_info_type => .{ .class_info_type = try ClassInfoType.read(data) },
            .method_type => .{ .method_type = try MethodType.read(data) },

            .ext_mod_class_ref => .{ .ext_mod_class_ref = try ExtModClassRef.read(data) },

            else => {
                std.debug.print("header_type = {}\n", .{self.header_type});
                unreachable;
            },
        };
    }
};

// term_name: TermName,
// type_name: TypeName,
// no_symbol: NoSymbol,
// type_symbol: TypeSymbol,
// alias_symbol: AliasSymbol,
// class_symbol: ClassSymbol,
// object_symbol: ObjectSymbol,
// method_symbol: MethodSymbol,
// ext_ref: ExtRef,
// ext_mod_class_ref: ExtModClassRef,
// no_type: NoType,
// no_prefix_type: NoPrefixType,
// this_type: ThisType,
// single_type: SingleType,
// constant_type: ConstantType,
// type_ref_type: TypeRefType,
// type_bounds_type: TypeBoundsType,
// refined_type: RefinedType,
// class_info_type: ClassInfoType,
// method_type: MethodType,
// poly_type: PolyType,
// //NullaryMethodType = 21, // overlapping?
// //method_type2 = 22,
// annotated_type: AnnotatedType,
// annotated_with_self_type: AnnotatedWithSelfType,
// existential_type: ExistentialType,

const SymbolTable = struct {
    major_version: u32,
    minor_version: u32,
    headers: []SymbolHeader,
    data: []u8,

    fn getName(self: SymbolTable, name: u32) []u8 {
        return self.headers[name].dataSlice(self.data);
    }

    fn read(data: []u8, allocator: std.mem.Allocator) !SymbolTable {
        var symbol_table: SymbolTable = undefined;

        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        symbol_table.major_version = try readVar(u32, reader);
        symbol_table.minor_version = try readVar(u32, reader);

        const symbol_count = try readVar(usize, reader);

        symbol_table.headers = try allocator.alloc(SymbolHeader, symbol_count);

        var i: usize = 0;
        while (i < symbol_count) {
            const offset = try stream.getPos();

            symbol_table.headers[i].header_type = @enumFromInt(try reader.readByte());
            symbol_table.headers[i].size = try readVar(u32, reader);
            symbol_table.headers[i].offset = offset;
            symbol_table.headers[i].header_size = @truncate(try stream.getPos() - offset);

            try reader.skipBytes(@intCast(symbol_table.headers[i].size), .{});
            i += 1;
        }

        symbol_table.data = data;

        return symbol_table;
    }

    fn debug(table: SymbolTable) void {
        std.debug.print("version = {}.{}, size = {}\n", .{
            table.major_version,
            table.minor_version,
            table.headers.len,
        });

        for (table.headers, 0..) |h, i| {
            std.debug.print("{d:>4}. header = {s:<18}, size = {d:>4}, offset = 0x{x:0>4}, data_offset = 0x{x:0>4}\n", .{
                i,
                @tagName(h.header_type),
                h.size,
                h.offset,
                h.dataOffset(),
            });
        }
    }
};

fn maxTagNameLength(e: anytype) u32 {
    var max_length: u32 = 0;
    inline for (@typeInfo(@TypeOf(e)).Enum.fields(e)) |field| {
        const length = field.name.len;
        if (length > max_length) {
            max_length = length;
        }
    }
    return max_length;
}
