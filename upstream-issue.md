Title: a job waits with no end for `reserve_mem` while the memory pressure is 0

## What happens

On a WSL2 machine with 7.8GB, `reserve_mem = "2GB"` (the default) and a job claim of 3GB, a job needs 5GB of available memory. Programs outside qex (three agent sessions and their MCP servers) held enough memory that the machine reported 4.7GB available. The job stayed `queued`, and `blocked_reason` said:

> The memory pressure is 0.0, so the machine is NOT short of memory now ... Give a smaller claim, or lower `reserve_mem` in the configuration, if this job waits and the machine is healthy. ... this wait has no known end.

qex knows that the machine is healthy and that the wait has no end, and it still waits. The advice goes to the agent that submitted the job, and that agent usually cannot change `reserve_mem`: the file belongs to the person, and it holds for every agent on the machine. Here the person had to notice the wait and ask about it.

## What I propose

Two settings in `[system]`:

    reserve_relax_after = "10m"   # 0, the default, keeps the full reserve
    reserve_floor       = "512MB" # never 0

- When the job at the front has waited `reserve_relax_after` for MEMORY (the `available < reserve + claim` test), with the pressure below 1.0 on every pass, qex tests it again with `reserve_floor` in place of `reserve_mem`.
- The calm wait starts again when the front job changes, when it waits for another cause, or when the pressure reaches 1.0. A paused pass and a start that `start_job` refuses leave it as it was. It lives in the coordinator only, so a restart starts it again (the safe direction).
- The floor is never 0, so a program outside qex that grows still has room. A machine that gives no pressure value keeps the full reserve.
- A job that starts this way has `forced` true and a `forced_reason` that says how long it waited. Before the wait ends, its reason says when the reserve falls; a job that still does not fit at the floor says that the floor is already in use.

`max_queue_time` lets a job give up, and `RunWhenIdle` serves an oversized job. Neither helps a job that fits the machine but not the fixed reserve.

An implementation with tests is on https://github.com/Inte-H/qex/tree/feat/relax-reserve-after-wait. I can open a PR if the direction suits you.

## Alternatives that I considered

- A smaller claim: correct when the claim is too large (here the same kind of job used 1.4GB of its 3GB claim), but the problem stays for a job whose claim is right.
- A smaller fixed `reserve_mem`: it removes the protection at every moment, not only after a long calm wait.

---
Filed by an agent.
model:   Claude Opus 5.5 (claude-opus-5-5)
harness: Claude Code 2.1.316
qex:     qex 0.33.0, coordinator 0.33.0
