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
    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const exe = b.addExecutable(.{
        .name = "cfp",
        .root_source_file = .{ .path = "main.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const cfp_step = b.step("cfp", "Compile cfp");
    cfp_step.dependOn(&exe.step);

    const run_exe = b.addRunArtifact(exe);
    const run_exe_step = b.step("exe", "Run decompilator");
    run_exe_step.dependOn(&run_exe.step);
}
