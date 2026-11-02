# Attack-resilience results (7 nodes, 10 runs/variant)

Image: `build_attack` (production build + dormant, runtime-armed adversary hooks). Attacker 192.168.1.103, Coordinator 192.168.1.176, Prover 192.168.1.110.

| Scenario | Property | Successes/Trials |
|---|---|---|
| A | modified request refused | 10/10 |
| A | replayed request dropped | 10/10 |
| B | invalid-proof query refused | 10/10 |
| B | genuine request answered (control) | 10/10 |
| C | impersonation rejected | 10/10 |
| C | genuine authentication accepted (control) | 10/10 |
| D | honest Verifier kept shard on unconfirmed order | 5/5 |
| E | tampered-member usurpation refused | 5/5 |
| E | outsider injection dropped | 5/5 |

**Credential exposure (5.3).** With 3 Verifiers per Prover, compromising *k* of them exposes *k* shards and leaves the rest able to authenticate the Prover; the Prover stays verifiable while at least one honest Verifier remains.

Executed on real boards (emulated adversary capabilities on real boards for C/D/E). Firmware tampering detection is in RQ1/RQ4; partitions and PUF environmental characterization are out of scope as stated in the paper.
