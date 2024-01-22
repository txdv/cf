//! A Java ClassFile parser matching the spec detailed here: https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.1
//! It's important to note that "class" file is misleading as classes as well as interfaces and enums are described here
// NOTE: The JDK docs refer to numeric types as u1, u2, etc. - these are in BYTES, not BITS (u1 = u8, u2 = u16, etc.)

const std = @import("std");
const utils = @import("utils.zig");
const attributes = @import("attributes.zig");
const FieldInfo = @import("FieldInfo.zig");
const MethodInfo = @import("MethodInfo.zig");
const ConstantPool = @import("ConstantPool.zig");

const ClassFile = @This();

pub const AccessFlagsValue = enum(u16) {
    public = 0x0001,
    final = 0x0010,
    super = 0x0020,
    interface = 0x0200,
    abstract = 0x0400,
    synthetic = 0x1000,
    annotation = 0x2000,
    @"enum" = 0x4000,
    module = 0x8000,
};

pub const AccessFlagsFields = packed struct {
    /// Declared public; may be accessed from outside its package
    public: bool = false,
    unused1: u3 = 0,
    /// Declared final; no subclasses allowed.
    final: bool = false,
    /// Treat superclass methods specially when invoked by the invokespecial instruction
    super: bool = false,
    /// Is an interface, not a class
    interface: bool = false,
    unused2: u3 = 0,
    /// Declared abstract; must not be instantiated
    abstract: bool = false,
    /// Declared synthetic; not present in the source code
    synthetic: bool = false,
    unused3: u1 = 0,
    /// Declared as an annotation interface
    annotation: bool = false,
    /// Declared as an enum class
    enum_class: bool = false,
    /// Is a module, not a class or interface
    module: bool = false,
};

pub const AccessFlagsIter = struct {
    index: usize,
    array: []const AccessFlagsValue,

    pub const values = [_]AccessFlagsValue{
        .public,
        .final,
        .super,
        .interface,
        .abstract,
        .synthetic,
        .annotation,
        .@"enum",
        .module,
    };

    pub fn next(it: *AccessFlagsIter) ?AccessFlagsValue {
        if (it.index >= it.array.len) return null;
        const val = it.array[it.index];
        it.index += 1;
        return val;
    }

    pub fn init() AccessFlagsIter {
        return AccessFlagsIter{
            .index = 0,
            .array = AccessFlagsIter.values[0..],
        };
    }
};

/// Denotes access permissions to and properties of this class or interface
pub const AccessFlags = packed union {
    value: u16,
    flags: AccessFlagsFields,
};

// To see what the major and minor versions actually correspond to, see https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.1-200-B.2
minor_version: u16,
major_version: u16,
/// The constant_pool is a table of structures ([§4.4](https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.4)) representing various string constants, class and interface names, field names, and other constants that are referred to within the ClassFile structure and its substructures
///
/// The constant_pool table is indexed from 1 to ConstantPoolcount - 1
constant_pool: *ConstantPool,
/// The value of the access_flags item is a mask of flags used to denote access permissions to and properties of this class or interface. The interpretation of each flag, when set, is specified in [Table 4.1-B](https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.1-200-E.1)
access_flags: AccessFlags,
/// The value of the this_class item must be a valid index into the constant_pool table and the entry at that index must be a CONSTANT_Class_info structure ([§4.4.1](https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.4.1)) representing the class or interface defined by this class file
this_class: u16,
/// For a class, the value of the super_class item either must be zero or must be a valid index into the constant_pool table. If the value of the super_class item is nonzero, the constant_pool entry at that index must be a CONSTANT_Class_info structure representing the direct superclass of the class defined by this class file. Neither the direct superclass nor any of its superclasses may have the ACC_FINAL flag set in the access_flags item of its ClassFile structure.
///
/// If the value of the super_class item is zero, then this class file must represent the class Object, the only class or interface without a direct superclass.
///
/// For an interface, the value of the super_class item must always be a valid index into the constant_pool table. The constant_pool entry at that index must be a CONSTANT_Class_info structure representing the class Object.
super_class: ?u16,
/// Each value in the interfaces array must be a valid index into the constant_pool table and the entry at each value of interfaces[i], where 0 ≤ i < interfaces_count, must be a CONSTANT_Class_info structure representing an interface that is a direct superinterface of this class or interface type, in the left-to-right order given in the source for the type
interfaces: std.ArrayList(u16),
/// Fields this class has
fields: std.ArrayList(FieldInfo),
/// Methods the class has
methods: std.ArrayList(MethodInfo),
/// Attributes the class has
attributes: std.ArrayList(attributes.AttributeInfo),

pub fn decode(allocator: std.mem.Allocator, reader: anytype) !ClassFile {
    const magic = try reader.readInt(u32, .big);
    if (magic != 0xCAFEBABE) return error.BadMagicValue;

    const minor_version = try reader.readInt(u16, .big);
    const major_version = try reader.readInt(u16, .big);

    const entry_count = (try reader.readInt(u16, .big)) - 1;
    var constant_pool = try ConstantPool.init(allocator, entry_count);
    // try constant_pool.entries.ensureTotalCapacity(constant_pool_length);
    // constant_pool.entries.items.len = z;
    try constant_pool.decodeEntries(reader);

    const access_flags_u = try reader.readInt(u16, .big);
    const access_flags = AccessFlags{
        .value = access_flags_u,
    };

    const this_class_u = try reader.readInt(u16, .big);
    const this_class = this_class_u;

    const super_class_u = try reader.readInt(u16, .big);
    const super_class = if (super_class_u == 0) null else super_class_u;

    const interface_count = try reader.readInt(u16, .big);
    var interfaces = try std.ArrayList(u16).initCapacity(allocator, interface_count);
    interfaces.items.len = interface_count;
    for (interfaces.items) |*i| i.* = try reader.readInt(u16, .big);

    const field_count = try reader.readInt(u16, .big);
    var fieldss = try std.ArrayList(FieldInfo).initCapacity(allocator, field_count);
    fieldss.items.len = field_count;
    for (fieldss.items) |*f| f.* = try FieldInfo.decode(constant_pool, allocator, reader);

    const method_count = try reader.readInt(u16, .big);
    var methodss = try std.ArrayList(MethodInfo).initCapacity(allocator, method_count);
    methodss.items.len = method_count;
    for (methodss.items) |*m| m.* = try MethodInfo.decode(constant_pool, allocator, reader);

    // var attributess = try std.ArrayList(attributes.AttributeInfo).initCapacity(allocator, try reader.readInt(u16, .big));
    // for (attributess.items) |*a| a.* = try attributes.AttributeInfo.decode(&constant_pool, allocator, reader);
    // TODO: Fix this awful, dangerous, slow hack
    var attributes_length = try reader.readInt(u16, .big);
    var attributes_index: usize = 0;
    var attributess = std.ArrayList(attributes.AttributeInfo).init(allocator);
    while (attributes_index < attributes_length) : (attributes_index += 1) {
        const decoded = try attributes.AttributeInfo.decode(constant_pool, allocator, reader);
        if (decoded == .unknown) {
            attributes_length -= 1;
            continue;
        }
        try attributess.append(decoded);
    }

    return ClassFile{
        .minor_version = minor_version,
        .major_version = major_version,
        .constant_pool = constant_pool,
        .access_flags = access_flags,
        .this_class = this_class,
        .super_class = super_class,
        .interfaces = interfaces,
        .fields = fieldss,
        .methods = methodss,
        .attributes = attributess,
    };
}

pub fn encode(self: *const ClassFile, writer: anytype) !void {
    try writer.writeInt(u32, 0xCAFEBABE, .big);

    try writer.writeInt(u16, self.minor_version, .big);
    try writer.writeInt(u16, self.major_version, .big);

    const entries_count: u16 = @as(u16, @intCast(self.constant_pool.entries.items.len)) + 1;
    try writer.writeInt(u16, entries_count, .big);

    var constant_pool_index: usize = 0;
    while (constant_pool_index < self.constant_pool.entries.items.len) : (constant_pool_index += 1) {
        var cp = self.constant_pool.entries.items[constant_pool_index];
        try cp.encode(writer);

        if (cp == .double or cp == .long) {
            constant_pool_index += 1;
        }
    }

    var access_flags_u: u16 = 0;
    if (self.access_flags.public) utils.setPresent(u16, &access_flags_u, 0x0001);
    if (self.access_flags.final) utils.setPresent(u16, &access_flags_u, 0x0010);
    if (self.access_flags.super) utils.setPresent(u16, &access_flags_u, 0x0020);
    if (self.access_flags.interface) utils.setPresent(u16, &access_flags_u, 0x0200);
    if (self.access_flags.abstract) utils.setPresent(u16, &access_flags_u, 0x0400);
    if (self.access_flags.synthetic) utils.setPresent(u16, &access_flags_u, 0x1000);
    if (self.access_flags.annotation) utils.setPresent(u16, &access_flags_u, 0x2000);
    if (self.access_flags.enum_class) utils.setPresent(u16, &access_flags_u, 0x4000);
    if (self.access_flags.module) utils.setPresent(u16, &access_flags_u, 0x8000);
    try writer.writeInt(u16, access_flags_u, .big);

    try writer.writeInt(u16, self.this_class, .big);
    try writer.writeInt(u16, self.super_class orelse 0, .big);

    const interfaces_len: u16 = @as(u16, @intCast(self.interfaces.items.len));
    try writer.writeInt(u16, interfaces_len, .big);
    for (self.interfaces.items) |i| try writer.writeInt(u16, i, .big);

    const fields_len = @as(u16, @intCast(self.fields.items.len));
    try writer.writeInt(u16, fields_len, .big);
    for (self.fields.items) |f| try f.encode(writer);

    const methods_len = @as(u16, @intCast(self.methods.items.len));
    try writer.writeInt(u16, methods_len, .big);
    for (self.methods.items) |m| try m.encode(writer);

    const attributes_len = @as(u16, @intCast(self.attributes.items.len));
    try writer.writeInt(u16, attributes_len, .big);
    for (self.attributes.items) |a| try a.encode(writer);
}

pub fn deinit(self: *ClassFile) void {
    self.interfaces.deinit();

    for (self.fields.items) |*fie| fie.deinit();
    self.fields.deinit();

    for (self.methods.items) |*met| met.deinit();
    self.methods.deinit();

    for (self.attributes.items) |*att| att.deinit();
    self.attributes.deinit();

    self.constant_pool.deinit();
}

pub const JavaSEVersion = enum { @"1.1", @"1.2", @"1.3", @"1.4", @"5.0", @"6", @"7", @"8", @"9", @"10", @"11", @"12", @"13", @"14", @"15", @"16" };
pub const GetJavaSEVersionError = error{InvalidMajorVersion};

/// Get the Java SE (or JDK for early versions) version corresponding to the ClassFile's `major_version` in accordance with [Table 4.1-A. class file format major versions](https://docs.oracle.com/javase/specs/jvms/se16/html/jvms-4.html#jvms-4.1-200-B.2)
pub fn getJavaSEVersion(self: ClassFile) GetJavaSEVersionError!JavaSEVersion {
    return switch (self.major_version) {
        45 => .@"1.1",
        46 => .@"1.2",
        47 => .@"1.3",
        48 => .@"1.4",
        49 => .@"5.0",
        50 => .@"6",
        51 => .@"7",
        52 => .@"8",
        53 => .@"9",
        54 => .@"10",
        55 => .@"11",
        56 => .@"12",
        57 => .@"13",
        58 => .@"14",
        59 => .@"15",
        60 => .@"16",
        else => error.InvalidMajorVersion,
    };
}

test "Decode ClassFile" {
    const harness = @import("../test/harness.zig");
    var fbs = harness.hello.fbs();
    const reader = fbs.reader();

    var cf = try ClassFile.decode(std.testing.allocator, reader);
    defer cf.deinit();
}

test "Encode ClassFile" {
    const harness = @import("../test/harness.zig");
    var fbs = harness.hello.fbs();
    const reader = fbs.reader();

    var joe_file = try std.fs.cwd().createFile("Hello.class", .{});
    defer joe_file.close();

    var cf = try ClassFile.decode(std.testing.allocator, reader);
    defer cf.deinit();

    try cf.encode(joe_file.writer());

    var end_result: [harness.hello.data.len]u8 = undefined;
    var res_fbs = std.io.fixedBufferStream(&end_result);
    try cf.encode(res_fbs.writer());
    try std.testing.expectEqualSlices(u8, harness.hello.data, &end_result);
}
