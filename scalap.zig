const std = @import("std");
const ClassFile = @import("src/ClassFile.zig");
const ConstantPool = @import("src/ConstantPool.zig");
const attributes = @import("src/attributes.zig");
const ClassAttributeInfo = attributes.AttributeInfo;
const Annotation = attributes.Annotation;
const RuntimeVisibleAnnotationsAttribute = attributes.RuntimeVisibleAnnotationsAttribute;

const Utils = @import("Utils.zig");
const FileData = Utils.FileData;

fn findScalaSig(cf: *ClassFile) ?[]u8 {
    for (cf.attributes.items) |attribute| {
        switch (attribute) {
            ClassAttributeInfo.runtime_visible_annotations => |runtime_annotation| {
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

fn readVar(comptime t: anytype, reader: anytype) !t {
    var result: t = 0;

    while (true) {
        const b: u8 = try reader.readByte();
        result |= (@as(t, b) & 0x7f);
        if ((b & 0x80) != 0x80) break;
        result = result << 7;
    }

    return result;
}

fn readVarData(comptime t: anytype, data: []u8) t {
    var result: t = 0;

    var pos: usize = 0;

    while (pos < data.len) {
        const b: u8 = data[pos];
        pos += 1;

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
        const table: SymbolTable = try SymbolTable.read(newSlice, allocator);

        table.debug();

        try table.print();
    }
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
};

const NullaryMethodType = struct {
    result_type: u32,

    fn read(data: []u8) !NullaryMethodType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return NullaryMethodType{
            .result_type = try readVar(u32, reader),
        };
    }
};

const PackedIterator = struct {
    pos: usize,
    refs: []const u8,

    fn next(it: *PackedIterator) ?u32 {
        if (it.pos >= it.refs.len) {
            return null;
        }

        var result: u32 = 0;

        while (it.pos < it.refs.len) {
            const b: u8 = it.refs[it.pos];
            it.pos += 1;

            result |= (@as(u32, b) & 0x7f);
            if ((b & 0x80) != 0x80) break;
            result = result << 7;
        }

        return result;
    }

    fn init(refs: []u8) PackedIterator {
        return PackedIterator{
            .pos = 0,
            .refs = refs,
        };
    }
};

const TypeRefs = struct {
    refs: []u8,

    fn iterator(self: TypeRefs) PackedIterator {
        return .{ .pos = 0, .refs = self.refs };
    }
};

const ClassInfoType = struct {
    symbol: u32,
    type_refs: TypeRefs,

    fn read(data: []u8) !ClassInfoType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return ClassInfoType{
            .symbol = try readVar(u32, reader),
            .type_refs = TypeRefs{ .refs = data[try stream.getPos()..] },
        };
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

    fn iterator(self: TypeRefType) PackedIterator {
        return .{ .pos = 0, .refs = self.type_args };
    }
};

const SymbolInfo = struct {
    name: u32,
    symbol: u32,
    flags: Flags,
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
        const flags = .{ .value = try readVar(u64, reader) };
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
    //poly_type = 21, // TODO: can be poly type for old versions?
    nullary_method_type = 21,
    //method_type2 = 22,
    constant_bool = 25,
    constant_long = 30,
    name_ref = 33,
    attribute_info = 40,
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
    //poly_type: PolyType,
    nullary_method_type: NullaryMethodType,
    //NullaryMethodType = 21, // overlapping?
    //method_type2 = 22,
    constant_bool: bool,
    constant_long: u64,
    name_ref: u32,
    attribute_info: AttributeInfo,
    annotated_type: AnnotatedType,
    annotated_with_self_type: AnnotatedWithSelfType,
    existential_type: ExistentialType,

    fn debug(header: Header, table: *const SymbolTable) void {
        _ = table;
        switch (header) {
            .term_name => |name| std.debug.print("TermName = \"{s}\"\n", .{name.name}),
            .type_name => |name| std.debug.print("TypeName = \"{s}\"\n", .{name.name}),
            .refined_type => |refined_type| {
                std.debug.print("{}\n", .{refined_type});
                std.debug.print("refined_type.type_refs = {}\n", .{refined_type.type_refs});
            },
            else => |item| std.debug.print("{}\n", .{item}),
        }
    }
};

const TermName = struct {
    name: []u8,

    fn read(data: []u8) TermName {
        return .{
            .name = data,
        };
    }
};

const TypeName = struct {
    name: []u8,

    fn read(data: []u8) TypeName {
        return .{
            .name = data,
        };
    }
};

const NoSymbol = struct {};

const TypeSymbol = struct {
    symbol: SymbolInfo,

    fn read(data: []u8) !TypeSymbol {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return .{
            .symbol = try SymbolInfo.read2(reader),
        };
    }
};

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

        return SingleType{
            .type_ref = try readVar(u32, reader),
            .symbol_ref = try readVar(u32, reader),
        };
    }
};

const ConstantType = struct {
    ref: u32,

    fn read(data: []u8) !ConstantType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return .{
            .ref = try readVar(u32, reader),
        };
    }
};

const TypeBoundsType = struct {
    fn read(data: []u8) !TypeBoundsType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        _ = reader;

        return .{};
    }
};

const RefinedType = struct {
    class_sym: u32,
    type_refs: TypeRefs,

    fn read(data: []u8) !RefinedType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        return RefinedType{
            .class_sym = try readVar(u32, reader),
            .type_refs = .{ .refs = data[try stream.getPos()..] },
        };
    }
};

const AnnotatedType = struct {};

const AnnotatedWithSelfType = struct {};

const ExistentialType = struct {
    fn read(data: []u8) ExistentialType {
        _ = data;
        return .{};
    }
};

const PolyType = struct {
    type_ref: u32,
    symbols: []u8,

    fn read(data: []u8) !PolyType {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return PolyType{
            .type_ref = try readVar(u32, reader),
            .symbols = data[try stream.getPos()..],
        };
    }
};

const AttributeInfo = struct {
    symbol: u32,
    type_ref: u32,

    fn read(data: []u8) !AttributeInfo {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        const symbol = try readVar(u32, reader);
        const type_ref = try readVar(u32, reader);
        const bytes = try reader.readByte();

        std.debug.print("test = {}\n", .{bytes});

        return AttributeInfo{
            .symbol = symbol,
            .type_ref = type_ref,
        };
    }
};

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
            .term_name => .{ .term_name = TermName.read(data) },
            .type_name => .{ .type_name = TypeName.read(data) },
            .no_symbol => .{ .no_symbol = .{} },
            .type_symbol => .{ .type_symbol = try TypeSymbol.read(data) },
            .alias_symbol => .{ .alias_symbol = .{} },
            .type_ref_type => .{ .type_ref_type = try TypeRefType.read(data) },
            .type_bounds_type => .{ .type_bounds_type = try TypeBoundsType.read(data) },

            .class_symbol => .{ .class_symbol = try ClassSymbol.read(data) },
            .object_symbol => .{ .object_symbol = .{ .symbol = try SymbolInfo.read(data) } },
            .method_symbol => .{ .method_symbol = try MethodSymbol.read(data) },
            .ext_ref => .{ .ext_ref = try ExtRef.read(data) },
            .ext_mod_class_ref => .{ .ext_mod_class_ref = try ExtModClassRef.read(data) },
            .no_type => .{ .no_type = .{} },
            .no_prefix_type => .{ .no_prefix_type = .{} },

            .this_type => .{ .this_type = try ThisType.read(data) },
            .single_type => .{ .single_type = try SingleType.read(data) },

            .refined_type => .{ .refined_type = try RefinedType.read(data) },
            .class_info_type => .{ .class_info_type = try ClassInfoType.read(data) },
            .method_type => .{ .method_type = try MethodType.read(data) },
            //.poly_type => .{ .poly_type = try PolyType.read(data) },
            .nullary_method_type => .{ .nullary_method_type = try NullaryMethodType.read(data) },
            .name_ref => .{ .name_ref = data[0] },
            .attribute_info => .{ .attribute_info = try AttributeInfo.read(data) },

            .constant_long => .{ .constant_long = readVarData(u64, data) },
            .constant_bool => .{ .constant_bool = data[0] != 0 },

            .existential_type => .{ .existential_type = ExistentialType.read(data) },

            .constant_type => .{ .constant_type = try ConstantType.read(data) },

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

const FlagValues = .{
    .{ .name = "implicit", .value = 0x00000001 },
    .{ .name = "final", .value = 0x00000002 },
    .{ .name = "private", .value = 0x00000004 },
    .{ .name = "protected", .value = 0x00000008 },

    .{ .name = "sealed", .value = 0x00000010 },
    .{ .name = "override", .value = 0x00000020 },
    .{ .name = "override", .value = 0x00000040 },
    .{ .name = "abstract", .value = 0x00000080 },
};

const FlagValue = struct { name: []u8, value: u32 };

const Flags = packed union {
    value: u64,
    flags: FlagsFields,

    fn hasFlag(it: Flags, flag: u64) bool {
        return it.value & flag != 0;
    }

    fn isImplicit() bool {
        return hasFlag(0x00000001);
    }

    // fn isImplicit() = hasFlag(0x00000001)
    // fn isFinal = hasFlag(0x00000002)
    // fn isPrivate = hasFlag(0x00000004)
    // def isProtected = hasFlag(0x00000008)
    //
    // def isSealed = hasFlag(0x00000010)
    // def isOverride = hasFlag(0x00000020)
    // def isCase = hasFlag(0x00000040)
    // def isAbstract = hasFlag(0x00000080)
    //
    // def isDeferred = hasFlag(0x00000100)
    // def isMethod = hasFlag(0x00000200)
    // def isModule = hasFlag(0x00000400)
    // def isInterface = hasFlag(0x00000800)
    //
    // def isMutable = hasFlag(0x00001000)
    // def isParam = hasFlag(0x00002000)
    // def isPackage = hasFlag(0x00004000)
    // def isDeprecated = hasFlag(0x00008000)
    //
    // def isCovariant = hasFlag(0x00010000)
    // def isCaptured = hasFlag(0x00010000)
    //
    // def isByNameParam = hasFlag(0x00010000)
    // def isContravariant = hasFlag(0x00020000)
    // def isLabel = hasFlag(0x00020000) // method symbol is a label. Set by TailCall
    // def isInConstructor = hasFlag(0x00020000) // class symbol is defined in this/superclass constructor
    //
    // def isAbstractOverride = hasFlag(0x00040000)
    // def isLocal = hasFlag(0x00080000)
    //
    // def isJava = hasFlag(0x00100000)
    // def isSynthetic = hasFlag(0x00200000)
    // def isStable = hasFlag(0x00400000)
    // def isStatic = hasFlag(0x00800000)
    //
    // def isCaseAccessor = hasFlag(0x01000000)
    // def isTrait = hasFlag(0x02000000)
    // def isBridge = hasFlag(0x04000000)
    // def isAccessor = hasFlag(0x08000000)
    //
    // def isSuperAccessor = hasFlag(0x10000000)
    // def isParamAccessor = hasFlag(0x20000000)
    //
    // def isModuleVar = hasFlag(0x40000000) // for variables: is the variable caching a module value
    // def isMonomorphic = hasFlag(0x40000000) // for type symbols: does not have type parameters
    // def isLazy = hasFlag(0x80000000L) // symbol is a lazy val. can't have MUTABLE unless transformed by typer
    //
    // def isError = hasFlag(0x100000000L)
    // def isOverloaded = hasFlag(0x200000000L)
    // def isLifted = hasFlag(0x400000000L)
    //
    // def isMixedIn = hasFlag(0x800000000L)
    // def isExistential = hasFlag(0x800000000L)
    //
    // def isExpandedName = hasFlag(0x1000000000L)
    // def isImplementationClass = hasFlag(0x2000000000L)
    // def isPreSuper = hasFlag(0x2000000000L)
};

const FlagsFields = packed struct {
    implicit: bool = false,
    final: bool = false,
    private: bool = false,
    protected: bool = false,

    sealed: bool = false,
    override: bool = false,
    case: bool = false,
    abstract: bool = false,

    deferred: bool = false,
    method: bool = false,
    module: bool = false,
    interface: bool = false,

    mutable: bool = false,
    param: bool = false,
    package: bool = false,
    deprecated: bool = false,

    covariant: bool = false,
    contravariant: bool = false,
    abstract_override: bool = false,
    local: bool = false,

    java: bool = false,
    synthetic: bool = false,
    stable: bool = false,
    static: bool = false,

    case_accessor: bool = false,
    trait: bool = false,
    bridge: bool = false,
    accessor: bool = false,

    super_accessor: bool = false,
    param_accessor: bool = false,
    module_var: bool = false,
    lazy: bool = false,

    is_error: bool = false,
    overloaded: bool = false,
    lifted: bool = false,
    mixed_in: bool = false,

    expanded_name: bool = false,
    implementation_class: bool = false,

    fn debug(it: FlagsFields) void {
        std.debug.print("flags = [", .{});
        var i: usize = 0;
        inline for (@typeInfo(FlagsFields).Struct.fields) |field| {
            if (@field(it, field.name)) {
                if (i > 0) {
                    std.debug.print(", ", .{});
                }
                std.debug.print("{s}", .{field.name});
                i += 1;
            }
        }
        std.debug.print("]\n", .{});
    }
};

const SymbolTable = struct {
    major_version: u32,
    minor_version: u32,
    headers: []SymbolHeader,
    h: []Header,
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

            const header_byte = try reader.readByte();
            std.debug.print("header_byte = {}\n", .{header_byte});
            symbol_table.headers[i].header_type = @enumFromInt(header_byte);
            symbol_table.headers[i].size = try readVar(u32, reader);
            symbol_table.headers[i].offset = offset;
            symbol_table.headers[i].header_size = @truncate(try stream.getPos() - offset);

            try reader.skipBytes(@intCast(symbol_table.headers[i].size), .{});
            i += 1;
        }

        symbol_table.data = data;

        symbol_table.h = try allocator.alloc(Header, symbol_count);

        for (symbol_table.headers, 0..) |header, j| {
            const header_data = header.dataSlice(symbol_table.data);

            symbol_table.h[j] = try SymbolHeader.read(header, &symbol_table, header_data);
        }

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

        std.debug.print("\n", .{});

        for (table.h, 0..) |h, i| {
            std.debug.print("{d:>4}. ", .{i});
            h.debug(&table);
        }

        std.debug.print("\n", .{});
    }

    fn lookupTermName(table: SymbolTable, index: u32) []u8 {
        return table.h[index].term_name.name;
    }

    fn lookupTypeName(table: SymbolTable, index: u32) []u8 {
        return table.h[index].type_name.name;
    }

    fn lookupName(table: SymbolTable, index: u32) []u8 {
        return switch (table.h[index]) {
            .term_name => |term_name| term_name.name,
            .type_name => |term_name| term_name.name,
            else => unreachable,
        };
    }

    fn print(table: SymbolTable) !void {
        const stdout = std.io.getStdOut();
        const writer = stdout.writer();

        switch (table.h[0]) {
            .object_symbol => |object_symbol| {
                try writer.print("object {s}", .{
                    table.lookupTermName(object_symbol.symbol.name),
                });
                const class_result = table.findClass(object_symbol.symbol.name).?;

                try table.printClass(writer, class_result.i);
            },
            .class_symbol => |class_symbol| {
                try writer.print("class {s}", .{
                    table.lookupTypeName(class_symbol.symbol.name),
                });
                try table.printClass(writer, 0);
            },
            else => {},
        }
    }

    fn printClass(table: SymbolTable, writer: anytype, class_index: usize) !void {
        const class_info_index = table.h[class_index].class_symbol.symbol.info;

        const class_info = table.h[class_info_index].class_info_type;

        var i: usize = 0;
        var iter = class_info.type_refs.iterator();
        while (iter.next()) |type_ref| {
            if (i == 0) {
                try writer.print(" extends ", .{});
            } else if (i == 1) {
                try writer.print(" with ", .{});
            }
            try table.printType(writer, type_ref);
            i += 1;
        }
        try writer.print(" {{\n", .{});

        for (table.h, 0..) |h, j| {
            switch (h) {
                .method_symbol => |method_symbol| {
                    if (method_symbol.symbol.symbol == class_index) {
                        std.debug.print("printMethod({})\n", .{j});
                        method_symbol.symbol.flags.flags.debug();
                        //std.debug.print("flags = {}\n", .{method_symbol.symbol.flags.flags});
                        try table.printMethod(writer, @truncate(j));
                    }
                },
                else => {},
            }
        }

        try writer.print("}}\n", .{});
    }

    fn printType(table: SymbolTable, writer: anytype, index: u32) !void {
        // h: Header
        const h = table.h[index];
        switch (h) {
            .type_symbol => |type_symbol| {
                try writer.print("{s}", .{table.lookupName(type_symbol.symbol.name)});
            },
            .type_ref_type => |type_ref_type| {
                try table.printType(writer, type_ref_type.type_ref);
                try writer.print(".", .{});
                try table.printType(writer, type_ref_type.symbol_ref);

                if (type_ref_type.type_args.len > 0) {
                    std.debug.print("ASD", .{});
                }
            },
            .this_type => |this_type| {
                try table.printType(writer, this_type.symbol);
            },
            .ext_mod_class_ref => |ext_mod_class_ref| {
                try writer.print("{s}", .{table.h[ext_mod_class_ref.name].term_name.name});
            },
            .ext_ref => |ext_ref| {
                try table.printType(writer, ext_ref.name);
            },
            .type_name => |type_name| {
                try writer.print("{s}", .{type_name.name});
            },
            .term_name => |term_name| {
                try writer.print("{s}", .{term_name.name});
            },
            .single_type => |single_type| {
                //try writer.print("single_type = {}\n", .{single_type});
                //try writer.print("single_type = {s}\n", .{table.h[single_type.symbol_ref].term_name.name});
                //try writer.print(.{single_type.symbol_ref});
                try table.printType(writer, single_type.symbol_ref);
            },
            .object_symbol => |object_symbol| {
                try table.printType(writer, object_symbol.symbol.symbol);
                try table.printType(writer, object_symbol.symbol.name);
                //std.debug.print("object_symbol => {}\n", .{object_symbol});
                //unreachable;
            },
            else => {
                std.debug.print("h => {}\n", .{h});
                unreachable;
            },
        }
    }

    fn printMethod(table: SymbolTable, writer: anytype, index: u32) !void {
        const h = table.h[index];
        switch (h) {
            .method_symbol => |method_symbol| {
                const name = table.lookupTermName(method_symbol.symbol.name);

                const is_constructor = std.mem.eql(u8, name, "<init>");

                const scala_name = if (is_constructor) "this" else name;

                if (method_symbol.symbol.flags.flags.private) {
                    return;
                }

                std.debug.print("method_name: {s}\n", .{scala_name});
                //std.debug.print("flags: {}\n", .{method_symbol.symbol.flags.flags});

                if (method_symbol.symbol.flags.flags.accessor) {
                    try writer.print("  val {s}", .{scala_name});
                } else {
                    try writer.print("  def {s}", .{scala_name});
                }

                switch (table.h[method_symbol.symbol.info]) {
                    .method_type => |method_type| {
                        try writer.print("(", .{});

                        var iter = PackedIterator.init(method_type.param_symbols);
                        var i: usize = 0;
                        while (iter.next()) |param_symbol| {
                            if (i > 0) {
                                try writer.print(", ", .{});
                            }
                            try table.printMethodArg(writer, param_symbol);
                            i += 1;
                        }
                        try writer.print(")", .{});

                        if (!is_constructor) {
                            try writer.print(": ", .{});
                            try table.printMethodReturnType(writer, method_type.result_type);
                        }
                        try writer.print(" = {{ /* compiled code */ }}\n", .{});
                    },
                    .nullary_method_type => |nullary_method_type| {
                        try writer.print(": ", .{});
                        try table.printMethodReturnType(writer, nullary_method_type.result_type);
                        try writer.print("\n", .{});
                    },
                    .refined_type => |refined_type| {
                        _ = refined_type;
                        try table.printMethodReturnType(writer, index);

                        //try writer.print("refined_type = {}\n", .{refined_type});
                        //unreachable;
                        //try table.printType(writer, );
                    },
                    .single_type => |single_type| {
                        //try writer.print("single_type = {}\n", .{single_type});
                        try table.printType(writer, single_type.type_ref);
                    },
                    else => {
                        std.debug.print("\n{}\n", .{table.h[method_symbol.symbol.info]});
                        unreachable;
                    },
                }
            },
            else => {},
        }
    }

    fn printMethodReturnType(table: SymbolTable, writer: anytype, index: u32) !void {
        const h = table.h[index];
        std.debug.print("==> ({}) {}\n", .{ index, h });
        switch (h) {
            .method_type => |method_type| {
                try writer.print("(", .{});

                var iter = PackedIterator.init(method_type.param_symbols);
                while (iter.next()) |param_symbol| {
                    try table.printMethodArg(writer, param_symbol);
                }
                try writer.print(")", .{});

                try writer.print(": ", .{});
                try table.printMethodReturnType(writer, method_type.result_type);
            },
            .type_name => |type_name| {
                try writer.print("{s}", .{type_name.name});
            },
            .type_ref_type => |type_ref_type| {
                try table.printMethodReturnType(writer, type_ref_type.symbol_ref);

                if (type_ref_type.type_args.len > 0) {
                    try writer.print("[", .{});

                    var i: usize = 0;
                    var iter = type_ref_type.iterator();
                    while (iter.next()) |type_arg| {
                        if (i > 0) {
                            try writer.print(", ", .{});
                        }

                        try table.printMethodReturnType(writer, type_arg);
                        i += 1;
                    }
                    try writer.print("]", .{});
                }
            },
            .this_type => |this_type| {
                try table.printMethodReturnType(writer, this_type.symbol);
            },
            .ext_mod_class_ref => |ext_mod_class_ref| {
                if (ext_mod_class_ref.symbol) |symbol| {
                    try table.printMethodReturnType(writer, symbol);
                } else {
                    const term_name = table.lookupTermName(ext_mod_class_ref.name);
                    try writer.print("{s}.", .{term_name});
                }
            },
            .ext_ref => |ext_ref| {
                if (ext_ref.symbol) |symbol| {
                    try table.printMethodReturnType(writer, symbol);
                }
                const term_name = table.lookupName(ext_ref.name);
                try writer.print("{s}", .{term_name});
            },
            .single_type => |single_type| {
                //_ = single_type;
                //try table.printMethodReturnType(writer, table.h[single_type.type_ref]);
                //try writer.print("{s}", .{single_type.type_ref});
                //unreachable;
                try table.printMethodReturnType(writer, single_type.symbol_ref);
            },
            .class_symbol => |class_symbol| {
                try table.printMethodReturnType(writer, class_symbol.symbol.symbol);
                const name = table.lookupName(class_symbol.symbol.name);
                try writer.print("{s}", .{name});
                //std.debug.print("NAME = {s}\n", .{name});
                //try table.printMethodReturnType(writer, class_symbol.symbol.info);
                std.debug.print("class_symbol = {}\n", .{class_symbol});
                //try table.printMethodReturnType(writer, table.h[class_symbol.symbol.name]);
            },
            .refined_type => |refined_type| {
                var iter = refined_type.type_refs.iterator();
                var i: usize = 0;
                while (iter.next()) |type_ref| {
                    if (i > 0) {
                        try writer.print(" with ", .{});
                    }
                    try table.printMethodType(writer, table.h[type_ref]);
                    i += 1;
                }
            },
            .type_symbol => {
                try table.printType(writer, index);
            },
            else => {
                switch (h) {
                    .method_symbol => {
                        std.debug.print("\nunreachable => {X}\n", .{h.method_symbol.symbol.flags.value});
                        h.method_symbol.symbol.flags.flags.debug();
                    },
                    else => {
                        std.debug.print("\nunreachable => {}\n", .{h});
                    },
                }

                unreachable;
            },
        }
    }

    const WriterError = error{
        AccessDenied,
        InputOutput,
        FileTooBig,
        SystemResources,
        NoSpaceLeft,
        DeviceBusy,
        Unexpected,
        WouldBlock,
        OperationAborted,
        BrokenPipe,
        ConnectionResetByPeer,
        DiskQuota,
        InvalidArgument,
        NotOpenForWriting,
        LockViolation,
    };

    fn printMethodType(table: SymbolTable, writer: anytype, h: Header) WriterError!void {
        switch (h) {
            .type_ref_type => |type_ref_type| {
                try table.printMethodType(writer, table.h[type_ref_type.type_ref]);
                try table.printMethodType(writer, table.h[type_ref_type.symbol_ref]);

                if (type_ref_type.type_args.len > 0) {
                    std.debug.print("ASD", .{});
                }
            },
            .this_type => |this_type| {
                try table.printMethodReturnType(writer, this_type.symbol);
            },
            .ext_mod_class_ref => |ext_mod_class_ref| {
                if (ext_mod_class_ref.symbol) |symbol| {
                    try table.printMethodType(writer, table.h[symbol]);
                }
                const term_name = table.lookupTermName(ext_mod_class_ref.name);
                if (!std.mem.eql(u8, term_name, "<empty>")) {
                    try writer.print("{s}.", .{term_name});
                }
            },
            .ext_ref => |ext_ref| {
                if (ext_ref.symbol) |symbol| {
                    try table.printMethodType(writer, table.h[symbol]);
                }
                const term_name = table.lookupTypeName(ext_ref.name);
                try writer.print("{s}", .{term_name});
            },
            else => {},
        }
    }

    fn printMethodArg(table: SymbolTable, writer: anytype, index: u32) !void {
        const h = table.h[index];
        std.debug.print("printMethodArg({}) = {}\n", .{ index, h });
        switch (h) {
            .method_symbol => |method_symbol| {
                const argName = table.lookupTermName(method_symbol.symbol.name);
                try writer.print("{s}: ", .{argName});
                try table.printMethodArg(writer, method_symbol.symbol.info);
            },
            .type_ref_type => |type_ref_type| {
                try table.printMethodArg(writer, type_ref_type.type_ref);
                try table.printMethodArg(writer, type_ref_type.symbol_ref);

                if (type_ref_type.type_args.len > 0) {
                    try writer.print("[", .{});

                    for (type_ref_type.type_args) |arg| {
                        try table.printMethodType(writer, table.h[arg]);
                        //try writer.print("{}", .{arg});
                    }

                    try writer.print("]", .{});
                }
            },
            .this_type => |this_type| {
                try table.printMethodArg(writer, this_type.symbol);
            },
            .single_type => {
                //try table.printMethodArg(writer, single_type.type_ref);
                //try table.printMethodArg(writer, single_type.symbol_ref);
                try table.printType(writer, index);
            },
            .ext_mod_class_ref => |ext_mod_class_ref| {
                const term_name = table.lookupTermName(ext_mod_class_ref.name);
                try writer.print("{s}.", .{term_name});
            },
            .ext_ref => |ext_ref| {
                const term_name = table.lookupTypeName(ext_ref.name);
                try writer.print("{s}", .{term_name});
            },
            .type_name => |type_name| {
                std.debug.print("debug = {s}\n", .{type_name.name});
            },
            else => {
                std.debug.print("debug = {}\n", .{h});
                unreachable;
            },
        }
    }

    fn findClass(table: SymbolTable, name: u32) ?struct { i: usize, class: ClassSymbol } {
        const n = table.lookupTermName(name);
        for (table.h, 0..) |header, i| {
            switch (header) {
                .class_symbol => |class_symbol| {
                    const class_name = table.lookupTypeName(class_symbol.symbol.name);
                    if (std.mem.eql(u8, n, class_name)) {
                        return .{ .i = i, .class = class_symbol };
                    }
                },
                else => {},
            }
        }
        return null;
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

const expect = std.testing.expect;

test "RefIterator iterates over packed refs" {
    var i: TypeRefs.Iterator = .{ .pos = 0, .refs = &[_]u8{ 115, 129, 60 } };

    try expect(i.pos == 0);

    try expect(i.next() == 115);
    try expect(i.pos == 1);

    try expect(i.next() == 188);
    try expect(i.pos == 3);

    try expect(i.next() == null);
}
