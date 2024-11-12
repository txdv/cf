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
    var shift: u5 = 0;

    while (true) {
        const b: u8 = try reader.readByte();
        result |= (@as(t, b) & 0x7f) << shift;
        if ((b & 0x80) != 0x80) break;
        shift += 7;
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
        const table = try readSymbolTable(newSlice, allocator);

        debugSymbolTable(table);
    }
}

const Header = enum(u8) {
    TermName = 0,
    TypeName = 1,
    NoSymbol = 2,
    TypeSymbol = 3,
    AliasSymbol = 4,
    ClassSymbol = 5,
    ObjectSymbol = 6,
    MethodSymbol = 7,
    ExtRef = 8,
    ExtModClassRef = 9,
    NoType = 10,
    NoPrefixType = 11,
    ThisType = 12,
    SingleType = 13,
    ConstantType = 14,
    TypeRefType = 15,
    TypeBoundsType = 16,
    RefinedType = 17,
    ClassInfoType = 18,
    MethodType = 19,
    PolyType = 20,
    NullaryMethodType = 21,
    MethodType2 = 22,
    AnnotatedType = 42,
    AnnotatedWithSelfType = 51,
    ExistentialType = 48,
};

const SymbolHeader = struct {
    header_type: Header,
    offset: u64,
    size: u32,
};

const SymbolTable = struct {
    major_version: u32,
    minor_version: u32,
    headers: []SymbolHeader,
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

fn debugSymbolTable(table: SymbolTable) void {
    std.debug.print("version = {}.{}, size = {}\n", .{
        table.major_version,
        table.minor_version,
        table.headers.len,
    });

    for (table.headers, 0..) |h, i| {
        std.debug.print("{d:>4}. header = {s:<15}, size = {d:>4}, offset = 0x{x:0>4}\n", .{
            i,
            @tagName(h.header_type),
            h.size,
            h.offset,
        });
    }
}

fn readSymbolTable(data: []u8, allocator: std.mem.Allocator) !SymbolTable {
    var symbol_table: SymbolTable = undefined;

    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();

    symbol_table.major_version = try readVar(u32, reader);
    symbol_table.minor_version = try readVar(u32, reader);

    const symbol_count = try readVar(usize, reader);

    symbol_table.headers = try allocator.alloc(SymbolHeader, symbol_count);

    var i: usize = 0;
    while (i < symbol_count) {
        const pos = try stream.getPos();
        symbol_table.headers[i] = try readHeader(pos, reader);
        i += 1;
    }

    return symbol_table;
}

fn readHeader(offset: u64, reader: anytype) !SymbolHeader {
    var header: SymbolHeader = undefined;
    header.header_type = @enumFromInt(try reader.readByte());
    header.size = try readVar(u32, reader);
    header.offset = offset;

    try reader.skipBytes(@intCast(header.size), .{});
    return header;
}
