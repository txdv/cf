const std = @import("std");
const ConstantPool = @import("ConstantPool.zig");
const utils = @import("utils.zig");

// TODO: Implement all attribute types
pub const AttributeInfo = union(enum) {
    constant_value: ConstantValueAttribute,
    runtime_visible_annotations: RuntimeVisibleAnnotationsAttribute,
    deprecated: DeprecatedAttribute,
    code: CodeAttribute,
    line_number_table: LineNumberTableAttribute,
    source_file: SourceFileAttribute,
    exceptions: ExceptionsAttribute,
    methodParameters: MethodParametersAttribute,
    unknown: UnknownAttribute,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) anyerror!AttributeInfo {
        const attribute_name_index = try reader.readInt(u16, .big);
        const attribute_length = try reader.readInt(u32, .big);

        const info = try allocator.alloc(u8, attribute_length);
        defer allocator.free(info);
        _ = try reader.readAll(info);

        var fbs = std.io.fixedBufferStream(info);
        const name = constant_pool.get(attribute_name_index).utf8.bytes;

        inline for (std.meta.fields(AttributeInfo)) |field| {
            if (field.type == void) {} else {
                const field_name = @field(field.type, "name");
                const is_unknown = std.mem.eql(u8, field_name, "Unknown");
                if (std.mem.eql(u8, field_name, name) and !is_unknown) {
                    return @unionInit(
                        AttributeInfo,
                        field.name,
                        try @field(field.type, "decode")(
                            constant_pool,
                            allocator,
                            fbs.reader(),
                        ),
                    );
                }
            }
        }

        return AttributeInfo{
            .unknown = try UnknownAttribute.decode_unknown(
                name,
                allocator,
                fbs.reader(),
            ),
        };
    }

    pub fn calcAttrLen(self: AttributeInfo) u32 {
        inline for (std.meta.fields(AttributeInfo)) |field| {
            if (field.type == void) continue;

            if (std.meta.activeTag(self) == @field(std.meta.Tag(AttributeInfo), field.name)) {
                return @field(self, field.name).calcAttrLen() + 6; // 6 intro bytes!
            }
        }

        unreachable;
    }

    pub fn deinit(self: *AttributeInfo) void {
        inline for (std.meta.fields(AttributeInfo)) |field| {
            if (field.type == void) continue;

            if (std.meta.activeTag(self.*) == @field(std.meta.Tag(AttributeInfo), field.name)) {
                @field(self, field.name).deinit();
            }
        }
    }

    pub fn encode(self: AttributeInfo, writer: anytype) !void {
        inline for (std.meta.fields(AttributeInfo)) |field| {
            if (field.type == void) continue;

            if (std.meta.activeTag(self) == @field(std.meta.Tag(AttributeInfo), field.name)) {
                var attr = @field(self, field.name);

                try writer.writeInt(u16, try attr.constant_pool.locateUtf8Entry(@field(field.type, "name")), .big);
                try writer.writeInt(u32, attr.calcAttrLen(), .big);

                try attr.encode(writer);
            }
        }
    }
};

pub const ExceptionTableEntry = packed struct {
    /// Where the exception handler becomes active (inclusive)
    start_pc: u16,
    /// Where it becomes inactive (exclusive)
    end_pc: u16,
    /// Start of handler
    handler_pc: u16,
    /// Index into constant pool
    catch_type: u16,

    pub fn decode(reader: anytype) !ExceptionTableEntry {
        var entry: ExceptionTableEntry = undefined;
        entry.start_pc = try reader.readInt(u16, .big);
        entry.end_pc = try reader.readInt(u16, .big);
        entry.handler_pc = try reader.readInt(u16, .big);
        entry.catch_type = try reader.readInt(u16, .big);
        return entry;
    }

    pub fn encode(self: ExceptionTableEntry, writer: anytype) !void {
        try writer.writeInt(u16, self.start_pc, .big);
        try writer.writeInt(u16, self.end_pc, .big);
        try writer.writeInt(u16, self.handler_pc, .big);
        try writer.writeInt(u16, self.catch_type, .big);
    }
};

pub const CodeAttribute = struct {
    pub const name = "Code";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    max_stack: u16,
    max_locals: u16,

    code: std.ArrayListUnmanaged(u8),
    exception_table: std.ArrayListUnmanaged(ExceptionTableEntry),

    attributes: std.ArrayListUnmanaged(AttributeInfo),

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !CodeAttribute {
        const max_stack = try reader.readInt(u16, .big);
        const max_locals = try reader.readInt(u16, .big);

        const code_length = try reader.readInt(u32, .big);
        var code = try std.ArrayListUnmanaged(u8).initCapacity(allocator, code_length);
        code.items.len = code_length;
        _ = try reader.readAll(code.items);

        const exception_table_len = try reader.readInt(u16, .big);
        var exception_table = try std.ArrayListUnmanaged(ExceptionTableEntry).initCapacity(allocator, exception_table_len);
        exception_table.items.len = exception_table_len;
        for (exception_table.items) |*et| et.* = try ExceptionTableEntry.decode(reader);

        var attributes_length = try reader.readInt(u16, .big);
        var attributes_index: usize = 0;
        var attributes = try std.ArrayListUnmanaged(AttributeInfo).initCapacity(allocator, attributes_length);
        while (attributes_index < attributes_length) : (attributes_index += 1) {
            const decoded = try AttributeInfo.decode(constant_pool, allocator, reader);
            if (decoded == .unknown) {
                attributes_length -= 1;
                continue;
            }
            try attributes.append(allocator, decoded);
        }

        return CodeAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,

            .max_stack = max_stack,
            .max_locals = max_locals,

            .code = code,
            .exception_table = exception_table,

            .attributes = attributes,
        };
    }

    pub fn calcAttrLen(self: CodeAttribute) u32 {
        const items_len: u32 = @as(u32, @intCast(self.code.items.len));
        var len: u32 = 2 + 2 + 4 + items_len + 2 + 2;
        for (self.attributes.items) |att| len += att.calcAttrLen();
        len += 8 * @as(u32, @intCast(self.exception_table.items.len));
        return len;
    }

    pub fn encode(self: CodeAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, self.max_stack, .big);
        try writer.writeInt(u16, self.max_locals, .big);

        try writer.writeInt(u32, @as(u32, @intCast(self.code.items.len)), .big);
        try writer.writeAll(self.code.items);

        try writer.writeInt(u16, @as(u16, @intCast(self.exception_table.items.len)), .big);
        for (self.exception_table.items) |et| try et.encode(writer);

        try writer.writeInt(u16, @as(u16, @intCast(self.attributes.items.len)), .big);
        for (self.attributes.items) |at| try at.encode(writer);
    }

    pub fn deinit(self: *CodeAttribute) void {
        self.code.deinit(self.allocator);
        self.exception_table.deinit(self.allocator);
        for (self.attributes.items) |*attr| {
            attr.deinit();
        }
        self.attributes.deinit(self.allocator);
    }
};

pub const LineNumberTableEntry = struct {
    /// The index into the code array at which the code for a new line in the original source file begins
    start_pc: u16,
    /// The corresponding line number in the original source file
    line_number: u16,

    pub fn decode(reader: anytype) !LineNumberTableEntry {
        var entry: LineNumberTableEntry = undefined;
        entry.start_pc = try reader.readInt(u16, .big);
        entry.line_number = try reader.readInt(u16, .big);
        return entry;
    }

    pub fn encode(self: LineNumberTableEntry, writer: anytype) !void {
        try writer.writeInt(u16, self.start_pc, .big);
        try writer.writeInt(u16, self.line_number, .big);
    }
};

pub const LineNumberTableAttribute = struct {
    pub const name = "LineNumberTable";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    line_number_table: std.ArrayListUnmanaged(LineNumberTableEntry),

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !LineNumberTableAttribute {
        const line_number_table_length = try reader.readInt(u16, .big);

        var line_number_table = try std.ArrayListUnmanaged(LineNumberTableEntry).initCapacity(allocator, line_number_table_length);
        line_number_table.items.len = line_number_table_length;
        for (line_number_table.items) |*entry| entry.* = try LineNumberTableEntry.decode(reader);

        return LineNumberTableAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,

            .line_number_table = line_number_table,
        };
    }

    pub fn calcAttrLen(self: LineNumberTableAttribute) u32 {
        const len: u32 = 2 + 4 * @as(u32, @intCast(self.line_number_table.items.len));
        return len;
    }

    pub fn encode(self: LineNumberTableAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, @as(u16, @intCast(self.line_number_table.items.len)), .big);
        for (self.line_number_table.items) |entry| try entry.encode(writer);
    }

    pub fn deinit(self: *LineNumberTableAttribute) void {
        self.line_number_table.deinit(self.allocator);
    }
};

pub const SourceFileAttribute = struct {
    pub const name = "SourceFile";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    source_file_index: u16,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !SourceFileAttribute {
        return SourceFileAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,

            .source_file_index = try reader.readInt(u16, .big),
        };
    }

    pub fn calcAttrLen(self: SourceFileAttribute) u32 {
        _ = self;
        return 2;
    }

    pub fn encode(self: SourceFileAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, self.source_file_index, .big);
    }

    pub fn deinit(self: *SourceFileAttribute) void {
        _ = self;
    }
};

pub const ExceptionsAttribute = struct {
    pub const name = "Exceptions";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    exception_index_table: std.ArrayListUnmanaged(u16),

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !ExceptionsAttribute {
        const exception_index_table_length = try reader.readInt(u16, .big);

        var exception_index_table = try std.ArrayListUnmanaged(u16).initCapacity(allocator, exception_index_table_length);
        exception_index_table.items.len = exception_index_table_length;
        for (exception_index_table.items) |*entry| entry.* = try reader.readInt(u16, .big);

        return ExceptionsAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,

            .exception_index_table = exception_index_table,
        };
    }

    pub fn calcAttrLen(self: ExceptionsAttribute) u32 {
        const len: u32 = 2 + 2 * @as(u32, @intCast(self.exception_index_table.items.len));
        return len;
    }

    pub fn encode(self: ExceptionsAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, @as(u16, @intCast(self.exception_index_table.items.len)), .big);
        for (self.exception_index_table.items) |entry| try writer.writeInt(u16, entry, .big);
    }

    pub fn deinit(self: *ExceptionsAttribute) void {
        self.exception_index_table.deinit(self.allocator);
    }
};

const MethodParameter = struct {
    const AccessFlagsValue = enum(u16) {
        final = 0x0010,
        synthetic = 0x1000,
        mandated = 0x8000,

        pub fn name(it: AccessFlagsValue) []const u8 {
            return switch (it) {
                .final => "final",
                .synthetic => "synthetic",
                .mandated => "mandated",
            };
        }
    };

    const AccessFlagsIter = utils.EnumIter(AccessFlagsValue);

    const AccessFlags = packed union {
        value: u16,

        pub fn iter(it: AccessFlags) AccessFlagsIter {
            return AccessFlagsIter{
                .value = it.value,
            };
        }
    };

    name_index: u16,
    access_flags: AccessFlags,

    pub fn name(it: MethodParameter, cp: *ConstantPool) []const u8 {
        return switch (cp.get(it.name_index)) {
            .utf8 => |utf8| utf8.bytes,
            else => unreachable,
        };
    }

    pub fn decode(reader: anytype) !MethodParameter {
        var entry: MethodParameter = undefined;
        entry.name_index = try reader.readInt(u16, .big);
        entry.access_flags.value = try reader.readInt(u16, .big);
        return entry;
    }
};

pub const MethodParametersAttribute = struct {
    const Self = @This();

    pub const name = "MethodParameters";

    allocator: std.mem.Allocator,
    parameters: std.ArrayListUnmanaged(MethodParameter),

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !Self {
        _ = constant_pool;

        const parameters_count = try reader.readInt(u8, .big);
        var parameters =
            try std.ArrayListUnmanaged(MethodParameter)
            .initCapacity(allocator, parameters_count);

        parameters.items.len = parameters_count;
        for (parameters.items) |*entry| entry.* = try MethodParameter.decode(reader);

        return MethodParametersAttribute{ .allocator = allocator, .parameters = parameters };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

pub const UnknownAttribute = struct {
    const Self = @This();
    pub const name = "Unknown";

    allocator: std.mem.Allocator,
    unknown_name: []const u8,
    data: []const u8,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !Self {
        _ = reader;
        _ = allocator;
        _ = constant_pool;
        unreachable;
    }

    pub fn decode_unknown(unknown_name: []u8, allocator: std.mem.Allocator, reader: anytype) !Self {
        return Self{
            .allocator = allocator,
            .unknown_name = unknown_name,
            .data = try reader.readAllAlloc(allocator, 400000),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

pub const ConstantValueAttribute = struct {
    pub const name = "ConstantValue";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    constantvalue_index: u16,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !ConstantValueAttribute {
        return ConstantValueAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,

            .constantvalue_index = try reader.readInt(u16, .big),
        };
    }

    pub fn calcAttrLen(self: ConstantValueAttribute) u32 {
        _ = self;
        return 2;
    }

    pub fn encode(self: ConstantValueAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, self.constantvalue_index, .big);
    }

    pub fn deinit(self: *ConstantValueAttribute) void {
        _ = self;
    }
};

pub const DeprecatedAttribute = struct {
    pub const name = "Deprecated";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !DeprecatedAttribute {
        _ = reader;
        return DeprecatedAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,
        };
    }

    pub fn calcAttrLen(self: DeprecatedAttribute) u32 {
        _ = self;
        return 0;
    }

    pub fn encode(self: DeprecatedAttribute, writer: anytype) anyerror!void {
        _ = self;
        _ = writer;
    }

    pub fn deinit(self: *DeprecatedAttribute) void {
        _ = self;
    }
};

// Annotations
pub const ElementTag = enum(u8) {
    // Primitive types
    Byte = 'B',
    Char = 'C',
    Double = 'D',
    Float = 'F',
    Int = 'I',
    Long = 'J',
    Short = 'S',
    Boolean = 'Z',

    // Other legal values
    String = 's',
    EnumConstant = 'e',
    Class = 'c',
    AnnotationType = '@',
    Array = '[',
};

pub const ElementValue = union(ElementTag) {
    Byte: u16,
    Char: u16,
    Double: u16,
    Float: u16,
    Int: u16,
    Long: u16,
    Short: u16,
    Boolean: u16,
    String: u16,
    EnumConstant: struct {
        type_name_index: u16,
        const_name_index: u16,
    },
    Class: u16,
    AnnotationType: *Annotation,
    Array: struct {
        num_values: u16,
        values: []ElementValue,
    },

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) anyerror!ElementValue {
        const value_tag = try reader.readEnum(ElementTag, .big);
        const value: ElementValue = switch (value_tag) {
            .Byte => .{ .Byte = try reader.readInt(u16, .big) },
            .Char => .{ .Char = try reader.readInt(u16, .big) },
            .Double => .{ .Double = try reader.readInt(u16, .big) },
            .Float => .{ .Float = try reader.readInt(u16, .big) },
            .Int => .{ .Int = try reader.readInt(u16, .big) },
            .Long => .{ .Long = try reader.readInt(u16, .big) },
            .Short => .{ .Short = try reader.readInt(u16, .big) },
            .Boolean => .{ .Boolean = try reader.readInt(u16, .big) },
            .String => .{ .String = try reader.readInt(u16, .big) },
            .EnumConstant => .{ .EnumConstant = .{
                .type_name_index = try reader.readInt(u16, .big),
                .const_name_index = try reader.readInt(u16, .big),
            } },
            .Class => .{ .Class = try reader.readInt(u16, .big) },
            .AnnotationType => annotation: {
                const annotation = try allocator.create(Annotation);
                annotation.* = try Annotation.decode(allocator, reader);
                break :annotation .{ .AnnotationType = annotation };
            },
            .Array => array: {
                const num_values = try reader.readInt(u16, .big);
                const values = try allocator.alloc(ElementValue, num_values);
                for (values) |*value| {
                    value.* = try ElementValue.decode(allocator, reader);
                }
                break :array .{ .Array = .{
                    .num_values = num_values,
                    .values = values,
                } };
            },
        };
        return value;
    }

    pub fn encode(self: ElementValue, writer: anytype) anyerror!void {
        try writer.writeInt(u16, @intFromEnum(self), .big);
        switch (self) {
            .EnumConstant => |econst| {
                try writer.writeInt(u16, econst.type_name_index, .big);
                try writer.writeInt(u16, econst.const_name_index, .big);
            },
            .AnnotationType => |anno| {
                try anno.encode(writer);
            },
            .Array => |array| {
                try writer.writeInt(u16, array.num_values, .big);
                for (array.values) |value| try value.encode(writer);
            },
            inline else => |value| try writer.writeInt(u16, value, .big),
        }
    }

    pub fn calcAttrLen(self: ElementValue) u32 {
        return switch (self) {
            .EnumConstant => 4,
            .AnnotationType => |anno| anno.calcAttrLen(),
            .Array => |array| 2 + array.num_values * 2,
            else => 2,
        };
    }

    pub fn deinit(self: ElementValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .AnnotationType => |anno| anno.deinit(allocator),
            .Array => |array| allocator.free(array.values),
            else => {},
        }
    }
};

pub const AnnotationValuePair = struct {
    element_name_index: u16,
    value: ElementValue,
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !AnnotationValuePair {
        const element_name_index = try reader.readInt(u16, .big);
        return AnnotationValuePair{
            .element_name_index = element_name_index,
            .value = try ElementValue.decode(allocator, reader),
        };
    }

    pub fn encode(self: AnnotationValuePair, writer: anytype) !void {
        try writer.writeInt(u16, self.element_name_index, .big);
        try self.value.encode(writer);
    }

    pub fn calcAttrLen(self: AnnotationValuePair) u32 {
        return 2 + self.value.calcAttrLen();
    }

    pub fn deinit(self: AnnotationValuePair, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
    }
};

pub const Annotation = struct {
    type_index: u16,
    num_element_value_pairs: u16,
    element_value_pairs: []AnnotationValuePair,
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Annotation {
        const type_index = try reader.readInt(u16, .big);
        const num_element_value_pairs = try reader.readInt(u16, .big);
        const element_value_pairs = try allocator.alloc(AnnotationValuePair, num_element_value_pairs);
        for (element_value_pairs) |*value_pair| {
            value_pair.* = try AnnotationValuePair.decode(allocator, reader);
        }

        return Annotation{
            .type_index = type_index,
            .num_element_value_pairs = num_element_value_pairs,
            .element_value_pairs = element_value_pairs,
        };
    }

    pub fn encode(self: Annotation, writer: anytype) !void {
        try writer.writeInt(u16, self.type_index, .big);
        try writer.writeInt(u16, self.num_element_value_pairs, .big);
        for (self.element_value_pairs) |pair| try pair.encode(writer);
    }

    pub fn calcAttrLen(self: Annotation) u32 {
        var len: u32 = 4;
        for (self.element_value_pairs) |pair| len += pair.calcAttrLen();
        return len;
    }

    pub fn deinit(self: Annotation, allocator: std.mem.Allocator) void {
        for (self.element_value_pairs) |value_pair| {
            value_pair.deinit(allocator);
        }
        allocator.free(self.element_value_pairs);
    }
};

pub const RuntimeVisibleAnnotationsAttribute = struct {
    pub const name = "RuntimeVisibleAnnotations";

    allocator: std.mem.Allocator,
    constant_pool: *ConstantPool,

    num_annotations: u16,
    annotations: []Annotation,

    pub fn decode(constant_pool: *ConstantPool, allocator: std.mem.Allocator, reader: anytype) !RuntimeVisibleAnnotationsAttribute {
        const num_annotations = try reader.readInt(u16, .big);
        const annotations = try allocator.alloc(Annotation, num_annotations);
        for (annotations) |*annotation| {
            annotation.* = try Annotation.decode(allocator, reader);
        }

        return RuntimeVisibleAnnotationsAttribute{
            .allocator = allocator,
            .constant_pool = constant_pool,
            .num_annotations = num_annotations,
            .annotations = annotations,
        };
    }

    pub fn calcAttrLen(self: RuntimeVisibleAnnotationsAttribute) u32 {
        var len: u32 = 2;
        for (self.annotations) |anno| len += anno.calcAttrLen();
        return len;
    }

    pub fn encode(self: RuntimeVisibleAnnotationsAttribute, writer: anytype) anyerror!void {
        try writer.writeInt(u16, self.num_annotations, .big);
        for (self.annotations) |annotation| try annotation.encode(writer);
    }

    pub fn deinit(self: *RuntimeVisibleAnnotationsAttribute) void {
        for (self.annotations) |annotation| annotation.deinit(self.allocator);
        self.allocator.free(self.annotations);
    }
};
