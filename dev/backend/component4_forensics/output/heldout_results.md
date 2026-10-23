# Held-out randomized test (100 scenarios, seed 2027)

Random scenarios (attacker address, hosts, ports, steps, timing, noise). Not used to tune the rules.

| Template | n | Method | Precision | Recall | F1 | Stage acc | Sequence | Asset F1 | Vector | Entry IP | Origin |
|---|---|---|---|---|---|---|---|---|---|---|---|
| remote_access | 25 | baseline | 0.13 | 1.00 | 0.22 | 0.76 | 0.58 | 0.89 | 8/25 | 25/25 | 0/25 |
| remote_access | 25 | improved | 0.83 | 1.00 | 0.90 | 1.00 | 1.00 | 1.00 | 25/25 | 25/25 | 25/25 |
| vpn_chain | 25 | baseline | 0.15 | 1.00 | 0.25 | 0.41 | 0.33 | 0.43 | 1/25 | 25/25 | 0/25 |
| vpn_chain | 25 | improved | 0.74 | 0.99 | 0.84 | 1.00 | 1.00 | 1.00 | 25/25 | 25/25 | 25/25 |
| insider | 25 | baseline | 0.12 | 1.00 | 0.21 | 0.84 | 0.45 | 1.00 | 24/25 | 0/25 | 0/25 |
| insider | 25 | improved | 0.88 | 1.00 | 0.93 | 1.00 | 1.00 | 1.00 | 25/25 | 25/25 | 25/25 |
| c2_beacon | 25 | baseline | 0.13 | 1.00 | 0.22 | 0.52 | 0.30 | 0.87 | 0/25 | 0/25 | 0/25 |
| c2_beacon | 25 | improved | 0.81 | 1.00 | 0.89 | 1.00 | 1.00 | 1.00 | 25/25 | 25/25 | 25/25 |
| ALL | 100 | baseline | 0.13 | 1.00 | 0.23 | 0.63 | 0.42 | 0.80 | 33/100 | 50/100 | 0/100 |
| ALL | 100 | improved | 0.82 | 1.00 | 0.89 | 1.00 | 1.00 | 1.00 | 100/100 | 100/100 | 100/100 |

## Weakest improved-method runs

| Template | Seed | TP | FP | FN | F1 | Vector | Entry | Origin | Assets F1 |
|---|---|---|---|---|---|---|---|---|---|
| vpn_chain | 2027107 | 15 | 21 | 0 | 0.59 | ok | ok | ok | 1.00 |
| vpn_chain | 2027101 | 11 | 15 | 0 | 0.59 | ok | ok | ok | 1.00 |
| vpn_chain | 2027114 | 12 | 12 | 2 | 0.63 | ok | ok | ok | 1.00 |
| vpn_chain | 2027100 | 13 | 14 | 0 | 0.65 | ok | ok | ok | 1.00 |
| vpn_chain | 2027103 | 10 | 9 | 0 | 0.69 | ok | ok | ok | 1.00 |
| vpn_chain | 2027113 | 17 | 15 | 0 | 0.69 | ok | ok | ok | 1.00 |
| c2_beacon | 2027323 | 13 | 10 | 0 | 0.72 | ok | ok | ok | 1.00 |
| vpn_chain | 2027104 | 13 | 9 | 0 | 0.74 | ok | ok | ok | 1.00 |
