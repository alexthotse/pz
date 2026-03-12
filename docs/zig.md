# Zig 0.15 Rules

AI-only reference. Telegraphic. No fluff. All facts.

## Knowledge Source

- Use known Zig 0.15 rules and this file first.
- Do not inspect Zig std/source for routine API questions.
- Read Zig source only when blocked on a repo-specific compile/runtime fact that this file does not cover.

## Comptime Dispatch (BLOCKING)

**NEVER if-chains for dispatch.** Use tables or StaticStringMap.

```zig
// FORBIDDEN:
if (s == b.@"foo".raw) return compileFoo();
if (s == b.@"bar".raw) return compileBar();

// CORRECT — table:
const dispatch = [_]struct{ sym: *const Value, handler: HandlerFn }{
    .{ .sym = &b.@"foo", .handler = compileFoo },
    .{ .sym = &b.@"bar", .handler = compileBar },
};
for (dispatch) |e| { if (s == e.sym.raw) return e.handler(self, args, env); }

// CORRECT — StaticStringMap:
const map = std.StaticStringMap(Handler).initComptime(.{
    .{ "foo", handleFoo },
    .{ "bar", handleBar },
});
if (map.get(name)) |h| return h(args);

// Set membership:
const valid = std.StaticStringMap(void).initComptime(.{ .{ "foo", {} }, .{ "bar", {} } });
return valid.has(name);
```

## ArrayList

Two variants. **Managed** stores allocator; **Unmanaged** doesn't.

```zig
// Managed — init(alloc), methods take no allocator:
var list = std.ArrayList(u32).init(alloc);
defer list.deinit();
try list.append(42);
const s = try list.toOwnedSlice();

// Unmanaged — .{} init, pass allocator to every method:
var list: std.ArrayListUnmanaged(u32) = .{};
defer list.deinit(alloc);
try list.append(alloc, 42);
const s = try list.toOwnedSlice(alloc);

// Batch:
try list.appendSlice(alloc, &[_]u32{ 1, 2, 3 });
```

## HashMap

```zig
// Managed:
var map = std.AutoHashMap(u32, []const u8).init(alloc);
defer map.deinit();
try map.put(42, "answer");
if (map.get(42)) |v| { _ = v; }
_ = map.contains(42);
_ = map.remove(42);

// Unmanaged:
var map: std.AutoHashMapUnmanaged(u32, []const u8) = .{};
defer map.deinit(alloc);
try map.put(alloc, 42, "answer");

// String keys: std.StringHashMap(V), std.StringHashMapUnmanaged(V)

// GetOrPut:
const gop = try map.getOrPut(alloc, key);
if (!gop.found_existing) gop.value_ptr.* = initial_value;
```

## I/O (0.15 — CHANGED)

```zig
// Stdout/stderr/stdin:
const stdout = std.fs.File.stdout();  // NOT std.io.getStdOut()
var buf: [4096]u8 = undefined;
const w = stdout.writer(&buf);  // writer takes buffer param
try w.print("hello {}\n", .{42});

// Allocating writer (dynamic buffer):
var aw: std.Io.Writer.Allocating = .init(alloc);
defer aw.deinit();
try aw.writer.print("{}", .{42});
// aw.toArrayList().items has bytes

// Fixed buffer stream:
var fbs = std.io.fixedBufferStream(&buf);
try fbs.writer().print("{d}", .{42});
const written = fbs.getWritten();

// File:
const f = try std.fs.cwd().createFile("out.txt", .{});
defer f.close();
try f.writeAll(data);

const f = try std.fs.cwd().openFile("in.txt", .{});
defer f.close();
const data = try f.readToEndAlloc(alloc, max_size);
```

## HTTP TLS

- `std.http.Client` owns `ca_bundle`; HTTPS requests pass `client.ca_bundle` into `std.crypto.tls.Client.init`.
- Custom CA bundle flow:
  - initialize `std.http.Client{ .allocator = alloc }`
  - clear/reset `client.ca_bundle`
  - `try client.ca_bundle.addCertsFromFilePathAbsolute(alloc, abs_pem_path)`
  - `@atomicStore(bool, &client.next_https_rescan_certs, false, .release)` to stop later system-root rescans from replacing the custom bundle

## Child Sandbox Hook

- `std.process.Child.spawnPosix` exposes no caller hook between `fork` and `exec`.
- If a subprocess needs pre-`exec` sandbox setup, `std.process.Child` is insufficient on its own.
- Real pre-`exec` sandboxing means manual `fork`/child setup/`exec` plumbing or an external sandbox launcher.

## Alignment

```zig
const ptr = try alloc.alignedAlloc(u8, .@"16", size);
// Enum: .@"1", .@"2", .@"4", .@"8", .@"16", .@"32", .@"64"
```

## Labeled Switch (State Machines)

```zig
const state: State = .start;  // MUST be const
state_loop: switch (state) {
    .start => {
        if (cond) continue :state_loop .number;  // transition
        return null;
    },
    .number => {
        i += 1;
        if (more) continue :state_loop .number;  // self-loop
        continue :state_loop .done;
    },
    .done => return i,
}
// Rules: const (not var), continue :label .tag (not bare continue)
```

## Testing

```zig
try std.testing.expectEqual(expected, actual);     // expected FIRST
try std.testing.expect(bool_condition);
try std.testing.expectEqualSlices(u32, exp, got);
try std.testing.expectEqualStrings("exp", got);
try std.testing.expectError(error.X, err_union);

// NEVER expectEqual on structs/slices — use ohsnap
// NEVER /// doc comments on test decls — use //
```

## Build + Snapshot Notes

- In `jj` repos, build metadata must not shell out to `git`. Use `jj log` or repository metadata already available to the build, or sibling workspaces will fail tests.
- `ohsnap` raw-value snapshots must include the rendered type header, not just the value body.
- When `ohsnap` needs to rewrite an existing snapshot, `<!update>` must be the first snapshot line, before the type header.
- In raw multiline `ohsnap` snapshots, quotes are literal after `\\`. Do not escape JSON quotes inside the snapshot body.
```zig
try oh.snap(@src(),
    \\[]u8
    \\  "value"
).expectEqual(got);
```
- `std.net.GetAddressListError` is private in Zig 0.15. Public repo APIs must not expose it; map resolver failures into repo-owned error sets.
- `std.net.Address` is an extern union. IPv4 bytes live at `addr.in.sa.addr`, IPv6 bytes at `addr.in6.sa.addr`, and `std.net.Address.eql(a, b)` is the right equality check.
- `ReplayReader.next()` returns arena-backed borrowed slices. If an event must survive another read, use a detached path such as `nextDup()`/`Event.dupe()`.
- `std.net.Stream.writer` needs a caller-owned buffer in Zig 0.15. If you do not need buffered streaming, write directly to the socket/file handle.

## Anti-Patterns (BLOCKING)

**1. Error masking:** No `catch unreachable` (unless provable). No `catch {}`. Use `try` or `catch |err| { log; return err; }`.

**2. String dispatch:** No `std.mem.eql(u8,...)` chains. Use StaticStringMap or interned IDs.

**3. Anonymous struct mismatch:** Return type `[]const struct{x:u32}` ≠ ArrayList element `struct{x:u32}`. Fix: name the struct.
```zig
const R = struct { x: u32 };  // named
fn foo() ![]const R { var l: std.ArrayList(R) = .{}; ... }
```

**4. Module boundary:** If `types.zig` registered as module `-Mtypes=...`, don't `@import("../../types.zig")` from root module. Use `@import("types")`.

**5. Switch on struct:** `switch (tok)` is error. Use `switch (tok.token_type)`.

## EnumSet

```zig
const E = enum { a, b, c };
const S = std.EnumSet(E);
var s = S.initEmpty();
s.insert(.a);
if (s.contains(.a)) { ... }
const n = s.count();
var it = s.iterator();
while (it.next()) |v| { _ = v; }
```

## Import Rules

```zig
// Import once:
const types = @import("type.zig");  // use types.Type, types.Foo

// Allocator always first param:
pub fn init(alloc: std.mem.Allocator, cap: usize) !Self { ... }
```

## Threads

```zig
const t = try std.Thread.spawn(.{}, worker, .{ arg1, arg2 });
t.join();
```

## Quick Ref

```
u8 i32 f64 bool void
[]const u8  [N]T  ?T  Error!T
std.ArrayList(T).init(alloc)          // managed
std.ArrayListUnmanaged(T) = .{}       // unmanaged
std.AutoHashMap(K,V).init(alloc)
std.StringHashMap(V).init(alloc)
std.StaticStringMap(V).initComptime(...)
std.EnumSet(E)
std.fs.File.stdout()
std.mem.eql(u8, a, b)                // equality only, not dispatch
```
