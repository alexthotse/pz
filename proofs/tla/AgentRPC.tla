---- MODULE AgentRPC ----
\* Parent-child agent RPC protocol for pz.
\* Models N concurrent children, handshake, run/cancel/out/done/err,
\* EOF (child crash), policy hash validation, and message routing.
\*
\* Sequence numbers are omitted: they are monotonic wire-level counters
\* verified in Zig (Stub.recv checks frame.seq > recv_seq). The protocol
\* properties we check here are state machine ordering and routing.

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Agents,          \* set of agent IDs
    MaxOut,          \* max Out messages per run (bounds state space)
    CorrectHash,     \* the "good" policy hash value
    BadHash          \* a mismatching policy hash value

VARIABLES
    pState,          \* pState[a] : parent stub state per agent
    cState,          \* cState[a] : child state per agent
    cHash,           \* cHash[a]  : hash the child will present
    pipe,            \* pipe[a]   : sequence of messages parent->child (bounded)
    rpipe,           \* rpipe[a]  : sequence of messages child->parent (bounded)
    runId,           \* runId[a]  : current run id (or "none")
    canceled,        \* canceled[a] : whether cancel was sent
    outCnt,          \* outCnt[a] : count of Out messages sent this run
    childAlive,      \* childAlive[a] : FALSE if child process crashed (EOF)
    ran              \* ran[a]    : TRUE after first run (bounds state space)

vars == <<pState, cState, cHash, pipe, rpipe,
          runId, canceled, outCnt, childAlive, ran>>

\* Message types on the wire
MsgHello(role, hash) == [type |-> "hello", role |-> role, hash |-> hash]
MsgRun(id)           == [type |-> "run", id |-> id]
MsgCancel(id)        == [type |-> "cancel", id |-> id]
MsgOut(id)           == [type |-> "out", id |-> id]
MsgDone(id)          == [type |-> "done", id |-> id]
MsgErr(id)           == [type |-> "err", id |-> id]

----

Init ==
    /\ pState     = [a \in Agents |-> "init"]
    /\ cState     = [a \in Agents |-> "init"]
    /\ cHash      = [a \in Agents |-> CorrectHash]
    /\ pipe       = [a \in Agents |-> <<>>]
    /\ rpipe      = [a \in Agents |-> <<>>]
    /\ runId      = [a \in Agents |-> "none"]
    /\ canceled   = [a \in Agents |-> FALSE]
    /\ outCnt     = [a \in Agents |-> 0]
    /\ childAlive = [a \in Agents |-> TRUE]
    /\ ran        = [a \in Agents |-> FALSE]

----
\* Parent sends Hello to child a.
ParentHello(a) ==
    /\ pState[a] = "init"
    /\ childAlive[a]
    /\ pState' = [pState EXCEPT ![a] = "wait_hello"]
    /\ pipe'   = [pipe EXCEPT ![a] = Append(@, MsgHello("parent", CorrectHash))]
    /\ UNCHANGED <<cState, cHash, rpipe, runId, canceled, outCnt, childAlive, ran>>

\* Child receives Hello, validates hash, replies.
ChildRecvHello(a) ==
    /\ cState[a] = "init"
    /\ childAlive[a]
    /\ Len(pipe[a]) > 0
    /\ Head(pipe[a]).type = "hello"
    /\ pipe' = [pipe EXCEPT ![a] = Tail(@)]
    /\ IF cHash[a] = CorrectHash
       THEN /\ cState' = [cState EXCEPT ![a] = "idle"]
            /\ rpipe'  = [rpipe EXCEPT ![a] = Append(@, MsgHello("child", CorrectHash))]
       ELSE /\ cState' = [cState EXCEPT ![a] = "rejected"]
            /\ rpipe'  = [rpipe EXCEPT ![a] = Append(@, MsgErr("none"))]
    /\ UNCHANGED <<pState, cHash, runId, canceled, outCnt, childAlive, ran>>

\* Parent receives child Hello reply.
ParentRecvHello(a) ==
    /\ pState[a] = "wait_hello"
    /\ Len(rpipe[a]) > 0
    /\ LET msg == Head(rpipe[a]) IN
       /\ rpipe' = [rpipe EXCEPT ![a] = Tail(@)]
       /\ IF msg.type = "hello" /\ msg.hash = CorrectHash
          THEN pState' = [pState EXCEPT ![a] = "idle"]
          ELSE pState' = [pState EXCEPT ![a] = "error"]
    /\ UNCHANGED <<cState, cHash, pipe, runId, canceled, outCnt, childAlive, ran>>

\* Parent sends Run to child a (at most once per agent to bound state space).
ParentRun(a) ==
    /\ pState[a] = "idle"
    /\ childAlive[a]
    /\ ~ran[a]
    /\ pState'  = [pState EXCEPT ![a] = "running"]
    /\ runId'   = [runId EXCEPT ![a] = a]
    /\ canceled' = [canceled EXCEPT ![a] = FALSE]
    /\ ran'     = [ran EXCEPT ![a] = TRUE]
    /\ pipe'    = [pipe EXCEPT ![a] = Append(@, MsgRun(a))]
    /\ UNCHANGED <<cState, cHash, rpipe, outCnt, childAlive>>

\* Child receives Run.
ChildRecvRun(a) ==
    /\ cState[a] = "idle"
    /\ childAlive[a]
    /\ Len(pipe[a]) > 0
    /\ Head(pipe[a]).type = "run"
    /\ cState' = [cState EXCEPT ![a] = "running"]
    /\ pipe'   = [pipe EXCEPT ![a] = Tail(@)]
    /\ outCnt' = [outCnt EXCEPT ![a] = 0]
    /\ UNCHANGED <<pState, cHash, rpipe, runId, canceled, childAlive, ran>>

\* Child sends Out (streaming output), bounded.
ChildSendOut(a) ==
    /\ cState[a] = "running"
    /\ childAlive[a]
    /\ outCnt[a] < MaxOut
    /\ rpipe' = [rpipe EXCEPT ![a] = Append(@, MsgOut(a))]
    /\ outCnt' = [outCnt EXCEPT ![a] = @ + 1]
    /\ UNCHANGED <<pState, cState, cHash, pipe, runId, canceled, childAlive, ran>>

\* Child sends Done (terminal).
ChildSendDone(a) ==
    /\ cState[a] = "running"
    /\ childAlive[a]
    /\ cState' = [cState EXCEPT ![a] = "idle"]
    /\ rpipe'  = [rpipe EXCEPT ![a] = Append(@, MsgDone(a))]
    /\ UNCHANGED <<pState, cHash, pipe, runId, canceled, outCnt, childAlive, ran>>

\* Child sends Err (terminal).
ChildSendErr(a) ==
    /\ cState[a] = "running"
    /\ childAlive[a]
    /\ cState' = [cState EXCEPT ![a] = "idle"]
    /\ rpipe'  = [rpipe EXCEPT ![a] = Append(@, MsgErr(a))]
    /\ UNCHANGED <<pState, cHash, pipe, runId, canceled, outCnt, childAlive, ran>>

\* Parent receives Out.
ParentRecvOut(a) ==
    /\ pState[a] = "running"
    /\ Len(rpipe[a]) > 0
    /\ Head(rpipe[a]).type = "out"
    /\ Head(rpipe[a]).id = a
    /\ rpipe' = [rpipe EXCEPT ![a] = Tail(@)]
    /\ UNCHANGED <<pState, cState, cHash, pipe, runId, canceled, outCnt, childAlive, ran>>

\* Parent receives Done.
ParentRecvDone(a) ==
    /\ pState[a] = "running"
    /\ Len(rpipe[a]) > 0
    /\ Head(rpipe[a]).type = "done"
    /\ Head(rpipe[a]).id = a
    /\ pState' = [pState EXCEPT ![a] = "idle"]
    /\ runId'  = [runId EXCEPT ![a] = "none"]
    /\ canceled' = [canceled EXCEPT ![a] = FALSE]
    /\ rpipe'  = [rpipe EXCEPT ![a] = Tail(@)]
    /\ UNCHANGED <<cState, cHash, pipe, outCnt, childAlive, ran>>

\* Parent receives Err.
ParentRecvErr(a) ==
    /\ pState[a] = "running"
    /\ Len(rpipe[a]) > 0
    /\ Head(rpipe[a]).type = "err"
    /\ pState' = [pState EXCEPT ![a] = "idle"]
    /\ runId'  = [runId EXCEPT ![a] = "none"]
    /\ canceled' = [canceled EXCEPT ![a] = FALSE]
    /\ rpipe'  = [rpipe EXCEPT ![a] = Tail(@)]
    /\ UNCHANGED <<cState, cHash, pipe, outCnt, childAlive, ran>>

\* Parent sends Cancel.
ParentCancel(a) ==
    /\ pState[a] = "running"
    /\ childAlive[a]
    /\ ~canceled[a]
    /\ canceled' = [canceled EXCEPT ![a] = TRUE]
    /\ pipe'     = [pipe EXCEPT ![a] = Append(@, MsgCancel(a))]
    /\ UNCHANGED <<pState, cState, cHash, rpipe, runId, outCnt, childAlive, ran>>

\* Child receives Cancel and acknowledges with Done.
ChildRecvCancel(a) ==
    /\ cState[a] = "running"
    /\ childAlive[a]
    /\ Len(pipe[a]) > 0
    /\ Head(pipe[a]).type = "cancel"
    /\ pipe' = [pipe EXCEPT ![a] = Tail(@)]
    /\ cState' = [cState EXCEPT ![a] = "idle"]
    /\ rpipe'  = [rpipe EXCEPT ![a] = Append(@, MsgDone(a))]
    /\ UNCHANGED <<pState, cHash, runId, canceled, outCnt, childAlive, ran>>

\* EOF: child crashes in any alive non-terminal state.
ChildCrash(a) ==
    /\ childAlive[a]
    /\ cState[a] \notin {"rejected", "dead"}
    /\ childAlive' = [childAlive EXCEPT ![a] = FALSE]
    /\ cState'     = [cState EXCEPT ![a] = "dead"]
    /\ UNCHANGED <<pState, cHash, pipe, rpipe, runId, canceled, outCnt, ran>>

\* Parent detects EOF on pipe (child crashed).
ParentDetectEOF(a) ==
    /\ ~childAlive[a]
    /\ pState[a] \in {"init", "wait_hello", "running"}
    /\ pState' = [pState EXCEPT ![a] = "error"]
    /\ runId'  = [runId EXCEPT ![a] = "none"]
    /\ canceled' = [canceled EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<cState, cHash, pipe, rpipe, outCnt, childAlive, ran>>

\* Inject a bad-hash child at init (nondeterministic).
BadHashChild(a) ==
    /\ cState[a] = "init"
    /\ cHash[a] = CorrectHash
    /\ cHash' = [cHash EXCEPT ![a] = BadHash]
    /\ UNCHANGED <<pState, cState, pipe, rpipe, runId, canceled, outCnt, childAlive, ran>>

----

\* Terminal: all agents have finished protocol (no more actions possible).
Terminated ==
    \A a \in Agents :
        pState[a] \in {"idle", "error"}

Next ==
    \/ \E a \in Agents :
        \/ ParentHello(a)
        \/ ChildRecvHello(a)
        \/ ParentRecvHello(a)
        \/ ParentRun(a)
        \/ ChildRecvRun(a)
        \/ ChildSendOut(a)
        \/ ChildSendDone(a)
        \/ ChildSendErr(a)
        \/ ParentRecvOut(a)
        \/ ParentRecvDone(a)
        \/ ParentRecvErr(a)
        \/ ParentCancel(a)
        \/ ChildRecvCancel(a)
        \/ ChildCrash(a)
        \/ ParentDetectEOF(a)
        \/ BadHashChild(a)
    \/ Terminated /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

----
\* ===================== SAFETY INVARIANTS =====================

\* Valid parent state machine values.
ValidParentStates ==
    \A a \in Agents :
        pState[a] \in {"init", "wait_hello", "idle", "running", "error"}

\* Valid child state machine values.
ValidChildStates ==
    \A a \in Agents :
        cState[a] \in {"init", "idle", "running", "rejected", "dead"}

\* No Out delivered before Run: if parent is not in running/error state,
\* no Out for this agent exists in rpipe.
\* (Error state may have stale undelivered Out from a crashed child.)
NoOutBeforeRun ==
    \A a \in Agents :
        pState[a] \in {"init", "wait_hello", "idle"} =>
            \A i \in 1..Len(rpipe[a]) :
                rpipe[a][i].type # "out" \/ rpipe[a][i].id # a

\* Policy hash checked before any Run: parent reaches "idle" (and thus
\* "running") only after successful Hello handshake with correct hash.
PolicyBeforeRun ==
    \A a \in Agents :
        pState[a] = "running" =>
            \/ cHash[a] = CorrectHash
            \/ ~childAlive[a]

\* No cross-routing: pipe[a] and rpipe[a] only carry messages for agent a.
NoCrossRouting ==
    \A a \in Agents :
        /\ \A i \in 1..Len(pipe[a]) :
               pipe[a][i].type = "hello" \/ pipe[a][i].id = a
        /\ \A i \in 1..Len(rpipe[a]) :
               rpipe[a][i].type = "hello" \/ rpipe[a][i].id \in {a, "none"}

\* Pipe lengths are bounded (model constraint sanity).
PipeBounded ==
    \A a \in Agents :
        /\ Len(pipe[a]) <= 3
        /\ Len(rpipe[a]) <= MaxOut + 2

TypeOK ==
    /\ ValidParentStates
    /\ ValidChildStates

SafetyInv ==
    /\ TypeOK
    /\ NoOutBeforeRun
    /\ PolicyBeforeRun
    /\ NoCrossRouting

----
\* ===================== LIVENESS =====================

\* Every Run eventually reaches Done, Err, or EOF (parent leaves "running").
RunCompletes ==
    \A a \in Agents :
        pState[a] = "running" ~> pState[a] \in {"idle", "error"}

\* Cancel propagates: if canceled, parent eventually leaves "running".
CancelCompletes ==
    \A a \in Agents :
        canceled[a] ~> pState[a] # "running"

====
