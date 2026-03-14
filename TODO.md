- Do note break LESSONS.md per session.
- Add file-level comments at the top, succintly explaining what the file is about.
- Do the same for types. 
- Use multi-line strings instead of `++` concatenation.
- Add an extra comma in patterns like this for `}, },` at the end so that the whole thing is formatted differently
```
            .usage => |usage| .{ .usage = .{
                .in_tok = usage.in_tok,
                .out_tok = usage.out_tok,
                .tot_tok = usage.tot_tok,
            } },
```
- Doesn't Zig use caps for global constants?
- Can development be set up such that temp work trees are in `/tmp`? Does `jj` require worktrees?  
- In a Zig union, is `void` the zero-bytes type for the arm that does not carry data, or is it `?void` or some other type? Google this!
- Make sure there are breaks between struct types, e.g. here
```
const Ev = core.providers.Ev;
const VScreen = vscreen.VScreen;
const Ui = harness.Ui;
const FrameSnap = struct {
    row0: []const u8,
    row1: []const u8,
    row8: []const u8,
    row9: []const u8,
};
const TableSnap = struct {
    counts: [5]usize,
    top: [3]usize,
    hdr: [3]usize,
    row1: [3]usize,
    row2: [3]usize,
    bot: [3]usize,
    corners: [9]u21,
    padding: [6]u21,
};
```

### `src/modes`

- The use of `mod.zig` looks like a vestige of Rust, fix?
- `src/modes/contract.zig` is `mode.zig`.
 - Why are we using `anyopaque` here instead of comptime?
 - `RunCtx` is just `Ctx` we can already scope it as `Mode.Ctx`, assuming `contract.zig` was renamed.
 - The tests are stupid since comptime would already ensure correctness here!
 
 ### `src/modes/print/errors.zig`
 
- Why are we mapping stop reason to errors in `mapStop`?
- Test is stupid. Why wouldn't map provide stable exit codes and messages? Zig would catch any missing switch arms at compile time!
- 
 
### `src/modes/print/run.zig`

- What are the tests here actually testing?
-

### `src/modes/tui/imgproto.zig`

- What is `ImageCap`? Types should have a comment or the full name should be `ImageCapture` if that's what it is.
- Why is this not `image.zig`? Better yet, why not `image.zig` and `Capture`?
- Why the stupd tests at the end?

### `src/modes/tui/cmdprev.zig`

- Rename to `cmdpreview.zig` as prev rings of previous.
- `CmdPreview` -> `Preview`.
- Is this a command preview or history navigation?
