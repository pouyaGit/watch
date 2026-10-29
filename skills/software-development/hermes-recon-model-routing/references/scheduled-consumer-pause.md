# Scheduled paid-consumer pause recipe

Use this only after proving a scheduled job is the paid consumer and no existing non-paid route preserves its behavior.

1. Read the live scheduler and identify the target job's command, monitor script, model, provider, frequency, last execution, and current state. Do not trust a historical report alone.
2. Read the shared control state and inspect every guard/admission component that can pause, resume, or reschedule the target. Pause any control job that could reopen the path; a direct target pause is not durable while a resume-capable guard remains active.
3. Apply only the scheduler-native `pause` action. Do not change `model`, `provider`, prompt, schedule, default config, or provider catalog. Preserve the original definition so rollback is `resume` of the same job IDs.
4. Use a read-only boundary timestamp at the first successful state change. Afterward verify all of: target `enabled=false` and `state=paused`; no target in-flight execution; no target execution row after the boundary; no target usage row after the boundary; no router/provider evidence of the paid route; Research/Jev state unchanged; protected source hashes unchanged; database `quick_check` succeeds.
5. Classify append-only growth in live recon tables separately from remediation mutation. A running daemon can add findings/assets/alerts while the read-only checks run. Do not call growth a remediation write, and do not claim whole-database identity when only protected Research/Jev tables are intended to be stable.
6. Validate the report mechanically after the final write. If a later daemon tick changes live counts, refresh the disclosed observation or timestamp before closing; the report and terminal block must derive from the same final snapshot.

## Decision table

| Situation | Safe action | Explicit non-action |
|---|---|---|
| Target job is pinned to a paid alias and no equivalent existing route is proven | Pause target; pause any resume-capable guard | No free remap, rotation, fallback, or default change |
| A non-paid existing route is proven equivalent and scoped to the job | Use the proven route only if the brief permits it | Do not infer equivalence from a catalog or historical use |
| Paused target still has an active resume-capable control path | Pause the control path too, then verify | Do not stop at target pause |
| Paid route is present in dormant job definitions | Disclose as dormant-but-routable | Do not claim the route was removed |
| Live daemon adds append-only recon rows during verification | Attribute by timestamp; compare protected Research/Jev rows separately | Do not delete or rewrite the rows |

## Reporting language

Use the execution-path distinction explicitly: `DEEPSEEK_ACTIVE_PATH: NO` can be correct for paused target jobs while the dormant definition still says `model=complex`; state both facts. `READY FOR PRODUCTION` remains `NO` when no equivalent non-paid replacement is certified. Report the exact post-boundary evidence and preserve the rollback commands without executing them.
