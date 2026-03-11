const std = @import("std");

pub const InitErr = error{
    InvalidMaxTries,
    InvalidBaseDelay,
    InvalidMaxDelay,
    InvalidMultiplier,
};

pub const StepErr = error{
    InvalidAttemptCount,
    InvalidFailureCount,
};

pub const Backoff = struct {
    base_ms: u64,
    max_ms: u64,
    mul: u16,

    pub const Init = struct {
        base_ms: u64,
        max_ms: u64,
        mul: u16 = 2,
    };

    pub fn init(cfg: Init) InitErr!Backoff {
        if (cfg.base_ms == 0) return error.InvalidBaseDelay;
        if (cfg.max_ms == 0 or cfg.max_ms < cfg.base_ms) return error.InvalidMaxDelay;
        if (cfg.mul == 0) return error.InvalidMultiplier;

        return .{
            .base_ms = cfg.base_ms,
            .max_ms = cfg.max_ms,
            .mul = cfg.mul,
        };
    }

    pub fn delayMs(self: Backoff, failures: u16) StepErr!u64 {
        if (failures == 0) return error.InvalidFailureCount;

        var delay = self.base_ms;
        var step: u16 = 1;
        while (step < failures and delay < self.max_ms) : (step += 1) {
            delay = self.mulCap(delay);
        }

        return delay;
    }

    fn mulCap(self: Backoff, cur: u64) u64 {
        if (cur >= self.max_ms) return self.max_ms;

        const mul_u64: u64 = @intCast(self.mul);
        if (cur > self.max_ms / mul_u64) return self.max_ms;

        const next = cur * mul_u64;
        if (next > self.max_ms) return self.max_ms;
        return next;
    }
};

pub const Step = union(enum) {
    retry_after_ms: u64,
    fail: void,
};

pub fn Policy(comptime E: type) type {
    return struct {
        max_tries: u16,
        backoff: Backoff,
        retryable: *const fn (err: E) bool,

        const Self = @This();

        pub const Init = struct {
            max_tries: u16,
            backoff: Backoff.Init,
            retryable: *const fn (err: E) bool,
        };

        pub fn init(cfg: Init) InitErr!Self {
            if (cfg.max_tries == 0) return error.InvalidMaxTries;

            return .{
                .max_tries = cfg.max_tries,
                .backoff = try Backoff.init(cfg.backoff),
                .retryable = cfg.retryable,
            };
        }

        pub fn next(self: Self, err: E, attempts_done: u16) StepErr!Step {
            if (attempts_done == 0) return error.InvalidAttemptCount;
            if (!self.retryable(err)) return .{ .fail = {} };
            if (attempts_done >= self.max_tries) return .{ .fail = {} };

            return .{
                .retry_after_ms = try self.backoff.delayMs(attempts_done),
            };
        }
    };
}

const RetryErr = error{
    Transient,
    Fatal,
};

const RetryPolicy = Policy(RetryErr);

fn retryOnTransient(err: RetryErr) bool {
    return err == error.Transient;
}

test "retry policy retries retryable errors until max tries" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Result = struct {
        step1: Step,
        step2: Step,
        step3: Step,
        fatal_step: Step,
    };
    const pol = try RetryPolicy.init(.{
        .max_tries = 3,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 60,
            .mul = 2,
        },
        .retryable = retryOnTransient,
    });

    const got = Result{
        .step1 = try pol.next(error.Transient, 1),
        .step2 = try pol.next(error.Transient, 2),
        .step3 = try pol.next(error.Transient, 3),
        .fatal_step = try pol.next(error.Fatal, 1),
    };

    try oh.snap(@src(),
        \\core.providers.retry.test.retry policy retries retryable errors until max tries.Result
        \\  .step1: core.providers.retry.Step
        \\    .retry_after_ms: u64 = 10
        \\  .step2: core.providers.retry.Step
        \\    .retry_after_ms: u64 = 20
        \\  .step3: core.providers.retry.Step
        \\    .fail: void = void
        \\  .fatal_step: core.providers.retry.Step
        \\    .fail: void = void
    ).expectEqual(got);
}

test "retry policy backoff is capped by max delay" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Result = struct {
        step1: Step,
        step2: Step,
        step3: Step,
    };
    const pol = try RetryPolicy.init(.{
        .max_tries = 5,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 25,
            .mul = 3,
        },
        .retryable = retryOnTransient,
    });

    const got = Result{
        .step1 = try pol.next(error.Transient, 1),
        .step2 = try pol.next(error.Transient, 2),
        .step3 = try pol.next(error.Transient, 3),
    };

    try oh.snap(@src(),
        \\core.providers.retry.test.retry policy backoff is capped by max delay.Result
        \\  .step1: core.providers.retry.Step
        \\    .retry_after_ms: u64 = 10
        \\  .step2: core.providers.retry.Step
        \\    .retry_after_ms: u64 = 25
        \\  .step3: core.providers.retry.Step
        \\    .retry_after_ms: u64 = 25
    ).expectEqual(got);
}

test "retry policy validates config and attempt counters" {
    try std.testing.expectError(error.InvalidMaxTries, RetryPolicy.init(.{
        .max_tries = 0,
        .backoff = .{
            .base_ms = 1,
            .max_ms = 2,
        },
        .retryable = retryOnTransient,
    }));

    try std.testing.expectError(error.InvalidBaseDelay, RetryPolicy.init(.{
        .max_tries = 1,
        .backoff = .{
            .base_ms = 0,
            .max_ms = 2,
        },
        .retryable = retryOnTransient,
    }));

    try std.testing.expectError(error.InvalidMaxDelay, RetryPolicy.init(.{
        .max_tries = 1,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 1,
        },
        .retryable = retryOnTransient,
    }));

    try std.testing.expectError(error.InvalidMultiplier, RetryPolicy.init(.{
        .max_tries = 1,
        .backoff = .{
            .base_ms = 1,
            .max_ms = 2,
            .mul = 0,
        },
        .retryable = retryOnTransient,
    }));

    const pol = try RetryPolicy.init(.{
        .max_tries = 2,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 30,
            .mul = 2,
        },
        .retryable = retryOnTransient,
    });

    try std.testing.expectError(error.InvalidAttemptCount, pol.next(error.Transient, 0));
    try std.testing.expectError(error.InvalidFailureCount, pol.backoff.delayMs(0));
}
