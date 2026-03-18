//! Configuration: env, settings.json, and CLI flag merging.
const std = @import("std");
const args = @import("args.zig");
const core = @import("../core.zig");

pub const model_default = "default";
pub const provider_default = "default";
pub const session_dir_default = ".pz/sessions";
pub const auto_cfg_path = ".pz/settings.json";
pub const policy_rel_path = ".pz/policy.json";

pub const Env = struct {
    model: ?[]const u8 = null,
    models: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    session_dir: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    theme: ?[]const u8 = null,
    provider_cmd: ?[]const u8 = null,
    home: ?[]const u8 = null,
    tmp_dir: ?[]const u8 = null,
    state_dir: ?[]const u8 = null,
    xdg_state_home: ?[]const u8 = null,

    pub const tmp_dir_default = "/tmp";

    /// Return TMPDIR or the default.
    pub fn tmpDir(self: Env) []const u8 {
        return self.tmp_dir orelse tmp_dir_default;
    }

    pub fn fromProcess(alloc: std.mem.Allocator) !Env {
        return .{
            .model = try dupEnv(alloc, "PZ_MODEL"),
            .models = try dupEnv(alloc, "PZ_MODELS"),
            .provider = try dupEnv(alloc, "PZ_PROVIDER"),
            .session_dir = try dupEnv(alloc, "PZ_SESSION_DIR"),
            .mode = try dupEnv(alloc, "PZ_MODE"),
            .theme = try dupEnv(alloc, "PZ_THEME"),
            .provider_cmd = try dupEnv(alloc, "PZ_PROVIDER_CMD"),
            .home = try validatedHome(alloc),
            .tmp_dir = try dupEnv(alloc, "TMPDIR"),
            .state_dir = try dupEnv(alloc, "PZ_STATE_DIR"),
            .xdg_state_home = try dupEnv(alloc, "XDG_STATE_HOME"),
        };
    }

    pub fn deinit(self: *Env, alloc: std.mem.Allocator) void {
        inline for (@typeInfo(Env).@"struct".fields) |f| {
            if (f.type == ?[]const u8) {
                if (@field(self, f.name)) |v| alloc.free(v);
            }
        }
        self.* = undefined;
    }
};

pub const Config = struct {
    mode: args.Mode,
    model: []u8,
    provider: []u8,
    session_dir: []u8,
    theme: ?[]u8 = null,
    provider_cmd: ?[]u8 = null,
    ca_file: ?[]u8 = null,
    enabled_models: ?[][]u8 = null, // model cycle list
    policy_lock: core.policy.Lock = .{},

    pub fn deinit(self: *Config, alloc: std.mem.Allocator) void {
        inline for (@typeInfo(Config).@"struct".fields) |f| {
            if (f.type == []u8) {
                alloc.free(@field(self, f.name));
            } else if (f.type == ?[]u8) {
                if (@field(self, f.name)) |v| alloc.free(v);
            } else if (f.type == ?[][]u8) {
                if (@field(self, f.name)) |models| {
                    for (models) |m| alloc.free(m);
                    alloc.free(models);
                }
            }
        }
        self.* = undefined;
    }
};

/// Validate a home path: reject empty, non-absolute, or null-byte-containing.
pub fn validateHome(home: ?[]const u8) ?[]const u8 {
    const h = home orelse return null;
    if (h.len == 0) return null;
    if (std.mem.indexOfScalar(u8, h, 0) != null) return null;
    if (!std.fs.path.isAbsolute(h)) return null;
    return h;
}

/// Read and validate HOME from env, allocating a copy. Called once at startup.
fn validatedHome(alloc: std.mem.Allocator) error{OutOfMemory}!?[]const u8 {
    const raw = try dupEnv(alloc, "HOME") orelse return null;
    if (validateHome(raw) != null) return raw;
    alloc.free(raw);
    return null;
}

pub const pz_state_dir = ".pz";
pub const pz_state_file = "state.json";

pub const PzState = struct {
    last_hash: ?[]const u8 = null,

    pub fn load(alloc: std.mem.Allocator, home: ?[]const u8) !?PzState {
        return loadForHome(alloc, home);
    }

    /// Load PzState from disk.
    /// Returns null when HOME is unset or state file is absent.
    /// Returns error for corrupt data, permission denied, OOM, etc.
    pub fn loadForHome(alloc: std.mem.Allocator, home_override: ?[]const u8) !?PzState {
        const path = (try statePathAlloc(alloc, home_override)) orelse return null;
        defer alloc.free(path);
        const raw = std.fs.cwd().readFileAlloc(alloc, path, 64 * 1024) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer alloc.free(raw);
        const parsed = try std.json.parseFromSlice(PzState, alloc, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();
        // Dupe fields so they outlive the parsed arena
        return .{
            .last_hash = if (parsed.value.last_hash) |h| (try alloc.dupe(u8, h)) else null,
        };
    }

    pub fn save(self: PzState, alloc: std.mem.Allocator, home: ?[]const u8) !void {
        try self.saveForHome(alloc, home);
    }

    pub fn saveForHome(self: PzState, alloc: std.mem.Allocator, home_override: ?[]const u8) !void {
        const home = home_override orelse return;
        const dir_path = try std.fs.path.join(alloc, &.{ home, pz_state_dir });
        defer alloc.free(dir_path);
        try core.fs_secure.ensureDirPath(dir_path);
        const path = try std.fs.path.join(alloc, &.{ dir_path, pz_state_file });
        defer alloc.free(path);
        const json = try std.json.Stringify.valueAlloc(alloc, self, .{});
        defer alloc.free(json);
        const file = try core.fs_secure.createFilePath(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(json);
    }

    pub fn deinit(self: *PzState, alloc: std.mem.Allocator) void {
        if (self.last_hash) |h| alloc.free(h);
        self.* = undefined;
    }
};

fn statePathAlloc(alloc: std.mem.Allocator, home_override: ?[]const u8) !?[]u8 {
    const home = home_override orelse return null;
    return try std.fs.path.join(alloc, &.{ home, pz_state_dir, pz_state_file });
}

/// Concrete error set covering all `discover()` failure paths:
/// policy loading, JSON parsing, filesystem access, and config validation.
pub const Err = @typeInfo(
    @typeInfo(@TypeOf(discover)).@"fn".return_type.?,
).error_union.error_set;

fn writeAutoCfg(dir: std.fs.Dir, data: []const u8) !void {
    try dir.makePath(".pz");
    try dir.writeFile(.{ .sub_path = auto_cfg_path, .data = data });
}

const SettingsCfg = struct {
    defaultModel: ?[]const u8 = null,
    model: ?[]const u8 = null,
    defaultProvider: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    sessionDir: ?[]const u8 = null,
    session_dir: ?[]const u8 = null,
    defaultMode: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    theme: ?[]const u8 = null,
    providerCommand: ?[]const u8 = null,
    provider_cmd: ?[]const u8 = null,
    caFile: ?[]const u8 = null,
    ca_file: ?[]const u8 = null,
    enabledModels: ?[]const []const u8 = null,
    models: ?[]const u8 = null,
};

test "pz state save and load are home-overrideable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home");
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home);

    var state = PzState{ .last_hash = try std.testing.allocator.dupe(u8, "abc123") };
    defer state.deinit(std.testing.allocator);
    try state.saveForHome(std.testing.allocator, home);

    var loaded = (try PzState.loadForHome(std.testing.allocator, home)) orelse return error.TestUnexpectedResult;
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("abc123", loaded.last_hash orelse return error.TestUnexpectedResult);
}

test "pz state save locks dir and file modes" {
    if (@import("builtin").os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home");
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home);

    var state = PzState{ .last_hash = try std.testing.allocator.dupe(u8, "abc123") };
    defer state.deinit(std.testing.allocator);
    try state.saveForHome(std.testing.allocator, home);

    const dir_path = try std.fs.path.join(std.testing.allocator, &.{ home, pz_state_dir });
    defer std.testing.allocator.free(dir_path);
    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();
    try std.testing.expectEqual(@as(std.fs.File.Mode, core.fs_secure.dir_mode), (try dir.stat()).mode & 0o777);

    const file_path = try std.fs.path.join(std.testing.allocator, &.{ dir_path, pz_state_file });
    defer std.testing.allocator.free(file_path);
    const st = try std.fs.cwd().statFile(file_path);
    try std.testing.expectEqual(@as(std.fs.File.Mode, core.fs_secure.file_mode), st.mode & 0o777);
}

test "pz state load returns null without overrideable home" {
    try std.testing.expect((try PzState.loadForHome(std.testing.allocator, null)) == null);
}

pub fn discover(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    parsed: args.Parsed,
    env: Env,
) !Config {
    var out = Config{
        .mode = .tui,
        .model = try alloc.dupe(u8, model_default),
        .provider = try alloc.dupe(u8, provider_default),
        .session_dir = try alloc.dupe(u8, session_dir_default),
    };
    errdefer out.deinit(alloc);

    const cwd = try dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const resolved = try core.policy.loadResolved(alloc, cwd, env.home);
    defer core.policy.deinitResolved(alloc, resolved);
    out.policy_lock = resolved.doc.lock;

    if (out.policy_lock.cfg) {
        switch (parsed.cfg) {
            .auto => {
                if (try hasFile(dir, auto_cfg_path)) return error.PolicyLockedConfig;
                if (try hasGlobalSettings(alloc, env.home)) return error.PolicyLockedConfig;
            },
            .off, .path => return error.PolicyLockedConfig,
        }
    } else if (try loadGlobalSettings(alloc, env.home)) |global_cfg| {
        defer global_cfg.deinit();
        try applySettingsCfg(alloc, &out, global_cfg.value, error.InvalidFileMode);
    }

    if (!out.policy_lock.cfg) {
        if (try loadFile(alloc, dir, parsed.cfg)) |file_cfg| {
            defer file_cfg.deinit();
            try applyRawCfg(
                alloc,
                &out,
                file_cfg.value.model,
                file_cfg.value.provider,
                file_cfg.value.session_dir,
                file_cfg.value.mode,
                file_cfg.value.theme,
                file_cfg.value.provider_cmd,
                pick(file_cfg.value.ca_file, file_cfg.value.caFile),
                error.InvalidFileMode,
            );
            if (file_cfg.value.models) |csv| {
                try setModels(alloc, &out, csv);
            }
        }
    }

    if (out.policy_lock.env) {
        if (env.model != null or
            env.models != null or
            env.provider != null or
            env.session_dir != null or
            env.mode != null or
            env.theme != null or
            env.provider_cmd != null)
        {
            return error.PolicyLockedEnv;
        }
    } else {
        try applyRawCfg(
            alloc,
            &out,
            env.model,
            env.provider,
            env.session_dir,
            env.mode,
            env.theme,
            env.provider_cmd,
            null,
            error.InvalidEnvMode,
        );

        if (env.models) |v| {
            try setModels(alloc, &out, v);
        }
    }

    if (out.policy_lock.cli) {
        if (parsed.mode_set or
            parsed.model != null or
            parsed.models != null or
            parsed.provider != null or
            parsed.session_dir != null or
            parsed.provider_cmd != null)
        {
            return error.PolicyLockedCli;
        }
    } else {
        if (parsed.mode_set) out.mode = parsed.mode;
        try applyRawCfg(
            alloc,
            &out,
            parsed.model,
            parsed.provider,
            parsed.session_dir,
            null,
            null,
            parsed.provider_cmd,
            null,
            error.InvalidMode,
        );

        if (parsed.models) |csv| {
            try setModels(alloc, &out, csv);
        }
    }

    if (out.policy_lock.system_prompt and
        (parsed.system_prompt != null or parsed.append_system_prompt != null))
    {
        return error.PolicyLockedSystemPrompt;
    }

    if (resolved.doc.ca_file) |v| {
        try replaceOptStr(alloc, &out.ca_file, v);
    }

    return out;
}

const FileCfg = struct {
    model: ?[]const u8 = null,
    models: ?[]const u8 = null, // comma-separated
    provider: ?[]const u8 = null,
    session_dir: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    theme: ?[]const u8 = null,
    provider_cmd: ?[]const u8 = null,
    caFile: ?[]const u8 = null,
    ca_file: ?[]const u8 = null,
};

fn loadFile(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    cfg_sel: args.ConfigSelection,
) !?std.json.Parsed(FileCfg) {
    const path = switch (cfg_sel) {
        .off => return null,
        .path => |p| p,
        .auto => if (hasFile(dir, auto_cfg_path) catch false) auto_cfg_path else return null,
    };

    const raw = try dir.readFileAlloc(alloc, path, 1024 * 1024);
    defer alloc.free(raw);

    const parsed = try std.json.parseFromSlice(FileCfg, alloc, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    return parsed;
}

fn loadGlobalSettings(alloc: std.mem.Allocator, home: ?[]const u8) !?std.json.Parsed(SettingsCfg) {
    const home_path = home orelse return null;
    if (home_path.len == 0) return null;
    if (std.mem.indexOfScalar(u8, home_path, 0) != null) return null;
    const path = try std.fs.path.join(alloc, &.{ home_path, auto_cfg_path });
    defer alloc.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidHomePath;

    var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();

    const raw = try file.readToEndAlloc(alloc, 1024 * 1024);
    defer alloc.free(raw);

    const parsed = try std.json.parseFromSlice(SettingsCfg, alloc, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    return parsed;
}

fn hasGlobalSettings(alloc: std.mem.Allocator, home: ?[]const u8) !bool {
    const home_path = home orelse return false;
    const path = try std.fs.path.join(alloc, &.{ home_path, auto_cfg_path });
    defer alloc.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidHomePath;

    std.fs.accessAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn applySettingsCfg(alloc: std.mem.Allocator, cfg: *Config, pi: SettingsCfg, comptime invalid_mode: anytype) !void {
    try applyRawCfg(
        alloc,
        cfg,
        pick(pi.model, pi.defaultModel),
        pick(pi.provider, pi.defaultProvider),
        pick(pi.session_dir, pi.sessionDir),
        pick(pi.mode, pi.defaultMode),
        pi.theme,
        pick(pi.provider_cmd, pi.providerCommand),
        pick(pi.ca_file, pi.caFile),
        invalid_mode,
    );
    if (pi.enabledModels) |arr| {
        try setModelsFromArray(alloc, cfg, arr);
    } else if (pi.models) |csv| {
        try setModels(alloc, cfg, csv);
    }
}

fn applyRawCfg(
    alloc: std.mem.Allocator,
    out: *Config,
    model: ?[]const u8,
    provider: ?[]const u8,
    session_dir: ?[]const u8,
    mode: ?[]const u8,
    theme: ?[]const u8,
    provider_cmd: ?[]const u8,
    ca_file: ?[]const u8,
    comptime invalid_mode: anytype,
) !void {
    if (model) |v| try replaceStr(alloc, &out.model, v);
    if (provider) |v| try replaceStr(alloc, &out.provider, v);
    if (session_dir) |v| try replaceStr(alloc, &out.session_dir, v);
    if (mode) |v| out.mode = try parseMode(v, invalid_mode);
    if (theme) |v| try replaceOptStr(alloc, &out.theme, v);
    if (provider_cmd) |v| try replaceOptStr(alloc, &out.provider_cmd, v);
    if (ca_file) |v| try replaceOptStr(alloc, &out.ca_file, v);
}

/// Parse comma-separated model list into enabled_models.
fn setModels(alloc: std.mem.Allocator, cfg: *Config, csv: []const u8) !void {
    var list = std.ArrayList([]u8).empty;
    errdefer {
        for (list.items) |m| alloc.free(m);
        list.deinit(alloc);
    }
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0) continue;
        try list.append(alloc, try alloc.dupe(u8, trimmed));
    }
    if (list.items.len == 0) return;
    // Free previous
    if (cfg.enabled_models) |old| {
        for (old) |m| alloc.free(m);
        alloc.free(old);
    }
    cfg.enabled_models = try list.toOwnedSlice(alloc);
}

/// Set enabled_models from a JSON string array (pi's enabledModels format).
fn setModelsFromArray(alloc: std.mem.Allocator, cfg: *Config, arr: []const []const u8) !void {
    if (arr.len == 0) return;
    var list = try alloc.alloc([]u8, arr.len);
    errdefer {
        for (list, 0..) |_, i| {
            if (i < arr.len) alloc.free(list[i]);
        }
        alloc.free(list);
    }
    for (arr, 0..) |m, i| {
        list[i] = try alloc.dupe(u8, m);
    }
    if (cfg.enabled_models) |old| {
        for (old) |m| alloc.free(m);
        alloc.free(old);
    }
    cfg.enabled_models = list;
}

fn pick(primary: ?[]const u8, fallback: ?[]const u8) ?[]const u8 {
    if (primary) |v| return v;
    return fallback;
}

fn hasFile(dir: std.fs.Dir, path: []const u8) !bool {
    dir.access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn parseMode(raw: []const u8, comptime invalid: anytype) @TypeOf(invalid)!args.Mode {
    return args.mode_map.get(raw) orelse invalid;
}

fn replaceStr(
    alloc: std.mem.Allocator,
    dst: *[]u8,
    src: []const u8,
) std.mem.Allocator.Error!void {
    const next = try alloc.dupe(u8, src);
    alloc.free(dst.*);
    dst.* = next;
}

fn replaceOptStr(
    alloc: std.mem.Allocator,
    dst: *?[]u8,
    src: []const u8,
) std.mem.Allocator.Error!void {
    const next = try alloc.dupe(u8, src);
    if (dst.*) |curr| alloc.free(curr);
    dst.* = next;
}

fn dupEnv(alloc: std.mem.Allocator, key: []const u8) error{OutOfMemory}!?[]const u8 {
    return std.process.getEnvVarOwned(alloc, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound, error.InvalidWtf8 => return null,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

test "config uses defaults when no sources are present" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .tui);
    try std.testing.expectEqualStrings(model_default, cfg.model);
    try std.testing.expectEqualStrings(provider_default, cfg.provider);
    try std.testing.expectEqualStrings(session_dir_default, cfg.session_dir);
    try std.testing.expect(cfg.theme == null);
    try std.testing.expect(cfg.provider_cmd == null);
    try std.testing.expect(cfg.ca_file == null);
}

test "config precedence is file then env then flags" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"mode\":\"print\",\"model\":\"file-model\",\"session_dir\":\"file-sessions\",\"theme\":\"light\",\"provider_cmd\":\"file-cmd\"}");

    const parsed = try args.parse(&.{ "--tui", "--model", "flag-model", "--provider-cmd", "flag-cmd" });
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{
        .model = "env-model",
        .provider = "env-provider",
        .session_dir = "env-sessions",
        .mode = "print",
        .theme = "dark",
        .provider_cmd = "env-cmd",
    });
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .tui);
    try std.testing.expectEqualStrings("flag-model", cfg.model);
    try std.testing.expectEqualStrings("env-provider", cfg.provider);
    try std.testing.expectEqualStrings("env-sessions", cfg.session_dir);
    try std.testing.expect(cfg.theme != null);
    try std.testing.expectEqualStrings("dark", cfg.theme.?);
    try std.testing.expect(cfg.provider_cmd != null);
    try std.testing.expectEqualStrings("flag-cmd", cfg.provider_cmd.?);
}

test "config no-config bypasses file source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"mode\":\"print\",\"model\":\"file-model\"}");

    const parsed = try args.parse(&.{"--no-config"});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .tui);
    try std.testing.expectEqualStrings(model_default, cfg.model);
    try std.testing.expectEqualStrings(provider_default, cfg.provider);
    try std.testing.expect(cfg.theme == null);
    try std.testing.expect(cfg.provider_cmd == null);
}

test "config explicit path loads file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "custom.json",
        .data = "{\"mode\":\"print\",\"model\":\"m\",\"session_dir\":\"s\",\"theme\":\"light\",\"provider_cmd\":\"cmd\",\"ca_file\":\"/etc/pz/custom.pem\"}",
    });

    const parsed = try args.parse(&.{ "--config", "custom.json" });
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .print);
    try std.testing.expectEqualStrings("m", cfg.model);
    try std.testing.expectEqualStrings(provider_default, cfg.provider);
    try std.testing.expectEqualStrings("s", cfg.session_dir);
    try std.testing.expect(cfg.theme != null);
    try std.testing.expectEqualStrings("light", cfg.theme.?);
    try std.testing.expect(cfg.provider_cmd != null);
    try std.testing.expectEqualStrings("cmd", cfg.provider_cmd.?);
    try std.testing.expect(cfg.ca_file != null);
    try std.testing.expectEqualStrings("/etc/pz/custom.pem", cfg.ca_file.?);
}

test "config rejects invalid env mode and invalid file mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const parsed = try args.parse(&.{});
    try std.testing.expectError(error.InvalidEnvMode, discover(
        std.testing.allocator,
        tmp.dir,
        parsed,
        .{
            .mode = "bad",
        },
    ));

    try writeAutoCfg(tmp.dir, "{\"mode\":\"bad\"}");
    try std.testing.expectError(error.InvalidFileMode, discover(
        std.testing.allocator,
        tmp.dir,
        parsed,
        .{},
    ));
}

test "config accepts interactive alias for mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{
        .mode = "interactive",
    });
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(cfg.mode == .tui);
}

test "config auto imports global settings from home" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.writeFile(.{
        .sub_path = "home/.pz/settings.json",
        .data =
        \\{
        \\  "defaultModel":"home-model",
        \\  "defaultProvider":"anthropic",
        \\  "sessionDir":"/tmp/home-sessions",
        \\  "defaultMode":"interactive",
        \\  "theme":"light",
        \\  "providerCommand":"home-provider-cmd",
        \\  "caFile":"/etc/pz/home-ca.pem"
        \\}
        ,
    });

    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{
        .home = home_abs,
    });
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .tui);
    try std.testing.expectEqualStrings("home-model", cfg.model);
    try std.testing.expectEqualStrings("anthropic", cfg.provider);
    try std.testing.expectEqualStrings("/tmp/home-sessions", cfg.session_dir);
    try std.testing.expect(cfg.theme != null);
    try std.testing.expectEqualStrings("light", cfg.theme.?);
    try std.testing.expect(cfg.provider_cmd != null);
    try std.testing.expectEqualStrings("home-provider-cmd", cfg.provider_cmd.?);
    try std.testing.expect(cfg.ca_file != null);
    try std.testing.expectEqualStrings("/etc/pz/home-ca.pem", cfg.ca_file.?);
}

test "config local auto file overrides global settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.writeFile(.{
        .sub_path = "home/.pz/settings.json",
        .data =
        \\{
        \\  "defaultModel":"home-model",
        \\  "defaultProvider":"home-provider",
        \\  "sessionDir":"home-sessions",
        \\  "defaultMode":"json",
        \\  "theme":"dark",
        \\  "providerCommand":"home-cmd",
        \\  "caFile":"home-ca.pem"
        \\}
        ,
    });
    try writeAutoCfg(tmp.dir, "{\"mode\":\"print\",\"model\":\"local-model\",\"provider\":\"local-provider\",\"session_dir\":\"local-sessions\",\"theme\":\"light\",\"provider_cmd\":\"local-cmd\",\"ca_file\":\"local-ca.pem\"}");

    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{
        .home = home_abs,
    });
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.mode == .print);
    try std.testing.expectEqualStrings("local-model", cfg.model);
    try std.testing.expectEqualStrings("local-provider", cfg.provider);
    try std.testing.expectEqualStrings("local-sessions", cfg.session_dir);
    try std.testing.expect(cfg.theme != null);
    try std.testing.expectEqualStrings("light", cfg.theme.?);
    try std.testing.expect(cfg.provider_cmd != null);
    try std.testing.expectEqualStrings("local-cmd", cfg.provider_cmd.?);
    try std.testing.expect(cfg.ca_file != null);
    try std.testing.expectEqualStrings("local-ca.pem", cfg.ca_file.?);
}

test "config policy ca_file overrides local config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"ca_file\":\"local-ca.pem\"}");
    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .ca_file = "policy-ca.pem",
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.ca_file != null);
    try std.testing.expectEqualStrings("policy-ca.pem", cfg.ca_file.?);
}

test "config rejects ca_file config under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"ca_file\":\"local-ca.pem\"}");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .ca_file = "policy-ca.pem",
        .lock = .{ .cfg = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{});
    try std.testing.expectError(error.PolicyLockedConfig, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config rejects explicit file override under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .cfg = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });
    try tmp.dir.writeFile(.{ .sub_path = "custom.json", .data = "{\"model\":\"x\"}" });

    const parsed = try args.parse(&.{ "--config", "custom.json" });
    try std.testing.expectError(error.PolicyLockedConfig, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config rejects no-config under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .cfg = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{"--no-config"});
    try std.testing.expectError(error.PolicyLockedConfig, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config rejects auto settings files under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    try writeAutoCfg(tmp.dir, "{\"model\":\"local\"}");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .cfg = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{});
    try std.testing.expectError(error.PolicyLockedConfig, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config rejects env overrides under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .env = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{});
    try std.testing.expectError(error.PolicyLockedEnv, discover(std.testing.allocator, tmp.dir, parsed, .{
        .model = "env-model",
    }));
}

test "config rejects cli overrides under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .cli = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{ "--model", "cli-model" });
    try std.testing.expectError(error.PolicyLockedCli, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config rejects system prompt override under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .system_prompt = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = policy_rel_path, .data = raw });

    const parsed = try args.parse(&.{ "--system-prompt", "sys" });
    try std.testing.expectError(error.PolicyLockedSystemPrompt, discover(std.testing.allocator, tmp.dir, parsed, .{}));
}

test "config loads enabled_models from --models flag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const parsed = try args.parse(&.{ "--models", "claude-opus-4-6,claude-haiku-4-5" });
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.enabled_models != null);
    const models = cfg.enabled_models.?;
    try std.testing.expectEqual(@as(usize, 2), models.len);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
    try std.testing.expectEqualStrings("claude-haiku-4-5", models[1]);
}

test "config loads enabled_models from file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"models\":\"model-a, model-b, model-c\"}");

    const parsed = try args.parse(&.{});
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.enabled_models != null);
    const models = cfg.enabled_models.?;
    try std.testing.expectEqual(@as(usize, 3), models.len);
    try std.testing.expectEqualStrings("model-a", models[0]);
    try std.testing.expectEqualStrings("model-b", models[1]);
    try std.testing.expectEqualStrings("model-c", models[2]);
}

test "config cli --models overrides file models" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAutoCfg(tmp.dir, "{\"models\":\"file-model\"}");

    const parsed = try args.parse(&.{ "--models", "cli-model" });
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.enabled_models != null);
    try std.testing.expectEqual(@as(usize, 1), cfg.enabled_models.?.len);
    try std.testing.expectEqualStrings("cli-model", cfg.enabled_models.?[0]);
}

test "config works with null HOME (env isolation)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const parsed = try args.parse(&.{});
    // Explicitly pass null home to prove no $HOME dependency
    var cfg = try discover(std.testing.allocator, tmp.dir, parsed, .{ .home = null });
    defer cfg.deinit(std.testing.allocator);

    // Should produce valid defaults without touching filesystem HOME
    try std.testing.expect(cfg.mode == .tui);
    try std.testing.expectEqualStrings(model_default, cfg.model);
    try std.testing.expectEqualStrings(provider_default, cfg.provider);
    try std.testing.expectEqualStrings(session_dir_default, cfg.session_dir);
    try std.testing.expect(cfg.theme == null);
    try std.testing.expect(cfg.provider_cmd == null);
    try std.testing.expect(cfg.ca_file == null);
}

test "PzState works with null HOME (env isolation)" {
    // load returns null, save is a no-op
    try std.testing.expect((try PzState.loadForHome(std.testing.allocator, null)) == null);

    var state = PzState{ .last_hash = null };
    try state.saveForHome(std.testing.allocator, null); // should not crash
}

fn testPolicyKeyPair() !core.signing.KeyPair {
    const seed = try core.signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    return core.signing.KeyPair.fromSeed(seed);
}
