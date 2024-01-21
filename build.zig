const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "cf",
        .root_source_file = .{
            .path = "cf.zig",
        },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const main_tests = b.addTest(.{ .root_source_file = .{ .path = "cf.zig" } });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
