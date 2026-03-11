const std = @import("std");
const pkg = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dep_opt = .{
        .target = target,
        .optimize = optimize,
    };
    const policy_pk_hex = b.option(
        []const u8,
        "policy-pk-hex",
        "Trusted Ed25519 public key for policy bundles",
    ) orelse "2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083";
    // zcheck's package build still shells out to git; import the module directly.
    const zcheck_mod = depMod(b, "zcheck", "src/zcheck.zig", target, optimize);

    // Build options: version, VCS hash, changelog
    const options = b.addOptions();
    options.addOption([]const u8, "version", pkg.version);

    var code: u8 = 0;
    const vcs_hash_raw = b.runAllowFail(
        &.{ "jj", "log", "--no-graph", "-r", "@", "-T", "commit_id.short()" },
        &code,
        .Ignore,
    ) catch "unknown";
    const vcs_hash = std.mem.trimRight(u8, vcs_hash_raw, "\n\r ");
    options.addOption([]const u8, "git_hash", vcs_hash);

    const vcs_log_raw = b.runAllowFail(
        &.{
            "jj",
            "log",
            "--no-graph",
            "-r",
            "ancestors(@, 50)",
            "-T",
            "commit_id.short() ++ \" \" ++ description.first_line() ++ \"\\n\"",
        },
        &code,
        .Ignore,
    ) catch "No commit history available";
    const vcs_log = std.mem.trimRight(u8, vcs_log_raw, "\n\r ");
    options.addOption([]const u8, "changelog", vcs_log);
    options.addOption([]const u8, "policy_pk_hex", policy_pk_hex);

    const exe = b.addExecutable(.{
        .name = "pz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addOptions("build_options", options);
    b.installArtifact(exe);

    const build_step = b.step("build", "Build the executable");
    build_step.dependOn(&exe.step);
    b.default_step.dependOn(build_step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.stdio = .inherit;
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run pz");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    if (b.lazyDependency("ohsnap", dep_opt)) |ohsnap_dep| {
        exe_tests.root_module.addImport("ohsnap", ohsnap_dep.module("ohsnap"));
    }
    exe_tests.root_module.addImport("zcheck", zcheck_mod);
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const suite_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/all_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    suite_tests.root_module.addOptions("build_options", options);
    if (b.lazyDependency("ohsnap", dep_opt)) |ohsnap_dep| {
        suite_tests.root_module.addImport("ohsnap", ohsnap_dep.module("ohsnap"));
    }
    suite_tests.root_module.addImport("zcheck", zcheck_mod);
    const run_suite_tests = b.addRunArtifact(suite_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_suite_tests.step);

    const perf_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/perf_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (b.lazyDependency("ohsnap", dep_opt)) |ohsnap_dep| {
        perf_tests.root_module.addImport("ohsnap", ohsnap_dep.module("ohsnap"));
    }
    perf_tests.root_module.addImport("zcheck", zcheck_mod);
    const run_perf_tests = b.addRunArtifact(perf_tests);
    const perf_step = b.step("perf", "Run performance budget tests");
    perf_step.dependOn(&run_perf_tests.step);

    const check_step = b.step("check", "Compile executable and tests");
    check_step.dependOn(&exe.step);
    check_step.dependOn(&exe_tests.step);
    check_step.dependOn(&suite_tests.step);
    check_step.dependOn(&perf_tests.step);
}

fn depMod(
    b: *std.Build,
    name: []const u8,
    sub_path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.fmt("{s}/{s}", .{ depRoot(b, name), sub_path }) },
        .target = target,
        .optimize = optimize,
    });
}

fn depRoot(b: *std.Build, name: []const u8) []const u8 {
    const pkgs = @import("root").dependencies.packages;

    for (b.available_deps) |dep| {
        const dep_name, const dep_hash = dep;
        if (!std.mem.eql(u8, dep_name, name)) continue;

        inline for (@typeInfo(pkgs).@"struct".decls) |decl| {
            if (std.mem.eql(u8, dep_hash, decl.name)) {
                return @field(pkgs, decl.name).build_root;
            }
        }
        unreachable;
    }

    std.debug.panic("missing dependency '{s}'", .{name});
}
