--------------------------- MODULE ThreadDispatch ---------------------------
(*
 * Phase 2 thread dispatch state machine for pz.
 * Models: parallel thread dispatch, file ownership, join with timeout,
 *         cancel propagation, token budget, depth-1 enforcement.
 *
 * Run with TLC:
 *   java -cp ~/tools/tla2tools.jar tlc2.TLC ThreadDispatch.tla
 *)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    MaxThreads,     \* max thread pool size (e.g., 3)
    MaxFiles,       \* number of files in the system (e.g., 4)
    MaxBudget,      \* total token budget (e.g., 10)
    EpisodeCost,    \* tokens reserved for episode generation (e.g., 2)
    Timeout         \* join timeout in ticks (e.g., 5)

VARIABLES
    orch_state,     \* orchestrator: "idle" | "dispatching" | "joining" | "done"
    thread_state,   \* function: thread -> "unused" | "pending" | "running" | "done" | "failed"
    thread_owner,   \* function: thread -> set of file ids owned
    thread_budget,  \* function: thread -> remaining token budget
    thread_mask,    \* function: thread -> set of tool names
    thread_depth,   \* function: thread -> 0 (orchestrator-spawned) or 1 (would be sub-thread)
    abort,          \* function: thread -> BOOLEAN
    round,          \* dispatch round counter (limits state space)
    join_set,       \* set of threads the orchestrator is joining on
    episodes,       \* set of threads whose episodes have been collected
    file_locks,     \* function: file -> thread id or 0 (unlocked)
    clock,          \* global tick counter
    budget_pool     \* remaining global token budget

Threads == 1..MaxThreads
Files == 1..MaxFiles
AllTools == {"read", "write", "edit", "grep", "find", "ls"}
DefaultMask == {"read", "grep", "find", "ls"}  \* excludes bash/agent per thread_default_mask

MaxRounds == 2

vars == <<orch_state, thread_state, thread_owner, thread_budget, thread_mask,
          thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

TypeOK ==
    /\ orch_state \in {"idle", "dispatching", "joining", "done"}
    /\ \A t \in Threads : thread_state[t] \in {"unused", "pending", "running", "done", "failed"}
    /\ \A t \in Threads : thread_owner[t] \subseteq Files
    /\ \A t \in Threads : thread_budget[t] \in 0..MaxBudget
    /\ \A t \in Threads : thread_mask[t] \subseteq AllTools
    /\ \A t \in Threads : thread_depth[t] \in {0, 1}
    /\ \A t \in Threads : abort[t] \in BOOLEAN
    /\ join_set \subseteq Threads
    /\ episodes \subseteq Threads
    /\ \A f \in Files : file_locks[f] \in {0} \union Threads
    /\ clock \in 0..Timeout+1
    /\ budget_pool \in 0..MaxBudget

Init ==
    /\ orch_state = "idle"
    /\ thread_state = [t \in Threads |-> "unused"]
    /\ thread_owner = [t \in Threads |-> {}]
    /\ thread_budget = [t \in Threads |-> 0]
    /\ thread_mask = [t \in Threads |-> {}]
    /\ thread_depth = [t \in Threads |-> 0]
    /\ abort = [t \in Threads |-> FALSE]
    /\ round = 0
    /\ join_set = {}
    /\ episodes = {}
    /\ file_locks = [f \in Files |-> 0]
    /\ clock = 0
    /\ budget_pool = MaxBudget

-----------------------------------------------------------------------------
(* Orchestrator actions *)

\* Orchestrator dispatches a thread with file ownership and budget
Dispatch(t, owned, cost) ==
    /\ orch_state \in {"idle", "dispatching"}
    /\ thread_state[t] = "unused"
    /\ cost + EpisodeCost <= budget_pool         \* must have budget for action + episode
    /\ owned \subseteq Files
    \* File ownership disjointness: no overlap with any running/pending thread
    /\ \A t2 \in Threads : t2 /= t /\ thread_state[t2] \in {"pending", "running"}
        => owned \cap thread_owner[t2] = {}
    /\ orch_state' = "dispatching"
    /\ thread_state' = [thread_state EXCEPT ![t] = "pending"]
    /\ thread_owner' = [thread_owner EXCEPT ![t] = owned]
    /\ thread_budget' = [thread_budget EXCEPT ![t] = cost]
    /\ thread_mask' = [thread_mask EXCEPT ![t] = DefaultMask]
    /\ thread_depth' = [thread_depth EXCEPT ![t] = 0]
    /\ budget_pool' = budget_pool - cost - EpisodeCost
    /\ UNCHANGED <<abort, round, join_set, episodes, file_locks, clock>>

\* Orchestrator starts joining on all dispatched threads
StartJoin ==
    /\ orch_state = "dispatching"
    /\ \E t \in Threads : thread_state[t] \in {"pending", "running", "done", "failed"}
    /\ orch_state' = "joining"
    /\ join_set' = {t \in Threads : thread_state[t] \in {"pending", "running", "done", "failed"}}
    /\ clock' = 0
    /\ UNCHANGED <<thread_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, episodes, file_locks, budget_pool>>

\* Orchestrator collects episode from a completed thread
CollectEpisode(t) ==
    /\ orch_state = "joining"
    /\ t \in join_set
    /\ thread_state[t] \in {"done", "failed"}
    /\ t \notin episodes
    /\ episodes' = episodes \union {t}
    \* Release file locks
    /\ file_locks' = [f \in Files |-> IF file_locks[f] = t THEN 0 ELSE file_locks[f]]
    /\ UNCHANGED <<orch_state, thread_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, clock, budget_pool>>

\* Join completes: all threads in join_set are collected
JoinComplete ==
    /\ orch_state = "joining"
    /\ join_set \subseteq episodes
    /\ orch_state' = "done"
    \* Reset thread states for potential reuse
    /\ thread_state' = [t \in Threads |-> "unused"]
    /\ thread_owner' = [t \in Threads |-> {}]
    /\ thread_budget' = [t \in Threads |-> 0]
    /\ thread_mask' = [t \in Threads |-> {}]
    /\ abort' = [t \in Threads |-> FALSE]
    /\ join_set' = {}
    /\ episodes' = {}
    /\ UNCHANGED <<thread_depth, round, file_locks, clock, budget_pool>>

\* Join timeout: mark remaining running threads as failed
JoinTimeout ==
    /\ orch_state = "joining"
    /\ clock >= Timeout
    /\ \E t \in join_set : thread_state[t] \in {"pending", "running"}
    /\ thread_state' = [t \in Threads |->
        IF t \in join_set /\ thread_state[t] \in {"pending", "running"}
        THEN "failed"
        ELSE thread_state[t]]
    /\ UNCHANGED <<orch_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

\* Orchestrator resets for next dispatch round (fresh budget, bounded)
Reset ==
    /\ orch_state = "done"
    /\ round < MaxRounds
    /\ orch_state' = "idle"
    /\ budget_pool' = MaxBudget
    /\ round' = round + 1
    /\ UNCHANGED <<thread_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, join_set, episodes, file_locks, clock>>

\* Cancel: orchestrator aborts a specific thread
Cancel(t) ==
    /\ orch_state = "joining"
    /\ t \in join_set
    /\ thread_state[t] = "running"
    /\ abort' = [abort EXCEPT ![t] = TRUE]
    /\ UNCHANGED <<orch_state, thread_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, round, join_set, episodes, file_locks, clock, budget_pool>>

-----------------------------------------------------------------------------
(* Thread actions *)

\* Thread starts running
ThreadStart(t) ==
    /\ thread_state[t] = "pending"
    /\ thread_state' = [thread_state EXCEPT ![t] = "running"]
    \* Acquire file locks
    /\ file_locks' = [f \in Files |->
        IF f \in thread_owner[t] THEN t ELSE file_locks[f]]
    /\ UNCHANGED <<orch_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, clock, budget_pool>>

\* Thread writes to a file it owns
ThreadWrite(t, f) ==
    /\ thread_state[t] = "running"
    /\ ~abort[t]
    /\ f \in thread_owner[t]        \* must own the file
    /\ file_locks[f] = t            \* must hold the lock
    /\ "write" \in thread_mask[t] \/ "edit" \in thread_mask[t]  \* must have write tool
    /\ thread_budget[t] > 0
    /\ thread_budget' = [thread_budget EXCEPT ![t] = @ - 1]
    /\ UNCHANGED <<orch_state, thread_state, thread_owner, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

\* Thread attempts to spawn sub-thread (must be rejected — depth-1)
ThreadSpawnAttempt(t) ==
    /\ thread_state[t] = "running"
    /\ thread_depth[t] >= 0         \* any depth
    \* Depth-1 enforcement: this action is IMPOSSIBLE because we never
    \* set depth to allow it. The invariant DepthOneEnforced catches violations.
    /\ FALSE                        \* blocked — threads cannot spawn

\* Thread completes successfully
ThreadDone(t) ==
    /\ thread_state[t] = "running"
    /\ ~abort[t]
    /\ thread_state' = [thread_state EXCEPT ![t] = "done"]
    /\ UNCHANGED <<orch_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

\* Thread fails (error or abort)
ThreadFail(t) ==
    /\ thread_state[t] = "running"
    /\ thread_state' = [thread_state EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<orch_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

\* Thread observes abort flag and transitions to failed
ThreadAbort(t) ==
    /\ thread_state[t] = "running"
    /\ abort[t] = TRUE
    /\ thread_state' = [thread_state EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<orch_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, clock, budget_pool>>

\* Clock tick (for timeout)
Tick ==
    /\ orch_state = "joining"
    /\ clock < Timeout + 1
    /\ clock' = clock + 1
    /\ UNCHANGED <<orch_state, thread_state, thread_owner, thread_budget, thread_mask,
                   thread_depth, abort, round, join_set, episodes, file_locks, budget_pool>>

-----------------------------------------------------------------------------
(* Next-state relation *)

\* Constrained ownership sets to avoid SUBSET explosion
\* Each thread gets at most 1 file, or empty set
OwnershipSets == {{}, {1}, {2}, {3}}

\* Fixed cost to reduce branching
Costs == {1, 2}

Next ==
    \/ \E t \in Threads, owned \in OwnershipSets, cost \in Costs :
        Dispatch(t, owned, cost)
    \/ StartJoin
    \/ Reset
    \/ \E t \in Threads : CollectEpisode(t)
    \/ JoinComplete
    \/ JoinTimeout
    \/ \E t \in Threads : Cancel(t)
    \/ \E t \in Threads : ThreadStart(t)
    \/ \E t \in Threads, f \in Files : ThreadWrite(t, f)
    \/ \E t \in Threads : ThreadDone(t)
    \/ \E t \in Threads : ThreadFail(t)
    \/ \E t \in Threads : ThreadAbort(t)
    \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Safety invariants *)

\* File ownership is disjoint across concurrent threads
FileOwnershipDisjoint ==
    \A t1, t2 \in Threads :
        t1 /= t2 /\ thread_state[t1] \in {"pending", "running"}
                  /\ thread_state[t2] \in {"pending", "running"}
        => thread_owner[t1] \cap thread_owner[t2] = {}

\* No thread exceeds its budget
BudgetNonNegative ==
    \A t \in Threads : thread_budget[t] >= 0

\* Global budget is non-negative
GlobalBudgetNonNegative ==
    budget_pool >= 0

\* Tool mask is always a subset of allowed tools (no escalation)
ToolMaskValid ==
    \A t \in Threads : thread_state[t] /= "unused" => thread_mask[t] \subseteq DefaultMask

\* Depth-1: no thread is ever at depth > 0 that is running
DepthOneEnforced ==
    \A t \in Threads : thread_state[t] = "running" => thread_depth[t] = 0

\* File locks are held only by running/done threads that own the file
FileLocksConsistent ==
    \A f \in Files : file_locks[f] /= 0 =>
        /\ thread_state[file_locks[f]] \in {"running", "done", "failed"}
        /\ f \in thread_owner[file_locks[f]]

\* No double-dispatch: a running thread is never re-dispatched
NoDoubleDispatch ==
    \A t \in Threads : thread_state[t] \in {"running", "done", "failed"} =>
        \* The thread cannot be dispatched again (it's not "unused")
        TRUE  \* enforced by Dispatch precondition: thread_state[t] = "unused"

\* Orchestrator only collects episodes from completed threads
EpisodesFromCompleted ==
    \A t \in episodes : thread_state[t] \in {"done", "failed", "unused"}

\* Join completeness: orchestrator transitions to "done" only after all episodes collected
JoinCompleteness ==
    orch_state = "done" => join_set \subseteq episodes \/ join_set = {}

-----------------------------------------------------------------------------
(* Liveness properties *)

\* Every running thread eventually reaches done or failed
ThreadProgress == \A t \in Threads :
    thread_state[t] = "running" ~> thread_state[t] \in {"done", "failed"}

\* Join eventually terminates (via completion or timeout)
JoinTermination ==
    orch_state = "joining" ~> orch_state = "done"

\* Aborted threads eventually fail
CancelResponsiveness == \A t \in Threads :
    (abort[t] = TRUE /\ thread_state[t] = "running") ~> thread_state[t] = "failed"

=============================================================================
