# Held-out randomized test (40 scenarios, seed 2026)

Random scenarios (attacker address, hosts, ports, steps, timing, noise). Not used to tune the rules.

| Template | n | Method | Precision | Recall | F1 | Stage acc | Sequence | Asset F1 | Vector | Entry IP | Origin |
|---|---|---|---|---|---|---|---|---|---|---|---|
| remote_access | 10 | baseline | 0.13 | 1.00 | 0.23 | 0.79 | 0.60 | 0.90 | 0/10 | 10/10 | 0/10 |
| remote_access | 10 | improved | 0.80 | 1.00 | 0.89 | 1.00 | 0.96 | 1.00 | 6/10 | 10/10 | 10/10 |
| vpn_chain | 10 | baseline | 0.15 | 1.00 | 0.27 | 0.48 | 0.34 | 0.45 | 0/10 | 10/10 | 0/10 |
| vpn_chain | 10 | improved | 0.76 | 1.00 | 0.86 | 1.00 | 0.92 | 1.00 | 10/10 | 10/10 | 10/10 |
| insider | 10 | baseline | 0.12 | 1.00 | 0.21 | 0.88 | 0.49 | 1.00 | 10/10 | 0/10 | 0/10 |
| insider | 10 | improved | 0.87 | 0.94 | 0.90 | 1.00 | 0.96 | 1.00 | 10/10 | 10/10 | 10/10 |
| c2_beacon | 10 | baseline | 0.12 | 1.00 | 0.22 | 0.55 | 0.32 | 0.88 | 0/10 | 0/10 | 0/10 |
| c2_beacon | 10 | improved | 0.81 | 0.99 | 0.88 | 1.00 | 0.92 | 1.00 | 10/10 | 10/10 | 10/10 |
| ALL | 40 | baseline | 0.13 | 1.00 | 0.23 | 0.67 | 0.44 | 0.81 | 10/40 | 20/40 | 0/40 |
| ALL | 40 | improved | 0.81 | 0.98 | 0.88 | 1.00 | 0.94 | 1.00 | 36/40 | 40/40 | 40/40 |

## Weakest improved-method runs

| Template | Seed | TP | FP | FN | F1 | Vector | Entry | Origin | Assets F1 |
|---|---|---|---|---|---|---|---|---|---|
| c2_beacon | 2026303 | 11 | 12 | 1 | 0.63 | ok | ok | ok | 1.00 |
| vpn_chain | 2026102 | 10 | 8 | 0 | 0.71 | ok | ok | ok | 1.00 |
| c2_beacon | 2026309 | 13 | 10 | 0 | 0.72 | ok | ok | ok | 1.00 |
| vpn_chain | 2026105 | 11 | 7 | 0 | 0.76 | ok | ok | ok | 1.00 |
| vpn_chain | 2026107 | 10 | 6 | 0 | 0.77 | ok | ok | ok | 1.00 |
| insider | 2026203 | 6 | 1 | 2 | 0.80 | ok | ok | ok | 1.00 |
| remote_access | 2026000 | 12 | 6 | 0 | 0.80 | ok | ok | ok | 1.00 |
| remote_access | 2026001 | 6 | 3 | 0 | 0.80 | ok | ok | ok | 1.00 |
