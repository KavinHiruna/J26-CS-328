# Evaluation Results - Baseline (Week 1) vs Improved (Week 2)

## scenario1_rdp_to_breaker
Records in scope: 49 | attack records: 21

| Metric | Baseline | Improved |
|---|---|---|
| Correlation precision | 0.44 | 1.00 |
| Correlation recall | 1.00 | 1.00 |
| Correlation F1 | 0.61 | 1.00 |
| Stage accuracy | 0.92 | 1.00 |
| Timeline sequence similarity | 0.64 | 1.00 |
| Compromised-asset F1 | 1.00 | 1.00 |
| RCA initial vector correct | NO | YES |
| RCA entry IP correct | YES | YES |
| RCA origin type correct | NO | YES |

False positives kept: baseline 27, improved 0. Missed attack records: baseline 0, improved 0.

## scenario2_vpn_lateral_ems
Records in scope: 44 | attack records: 15

| Metric | Baseline | Improved |
|---|---|---|
| Correlation precision | 0.34 | 1.00 |
| Correlation recall | 1.00 | 1.00 |
| Correlation F1 | 0.51 | 1.00 |
| Stage accuracy | 0.27 | 1.00 |
| Timeline sequence similarity | 0.35 | 1.00 |
| Compromised-asset F1 | 0.00 | 1.00 |
| RCA initial vector correct | NO | YES |
| RCA entry IP correct | YES | YES |
| RCA origin type correct | NO | YES |

False positives kept: baseline 29, improved 0. Missed attack records: baseline 0, improved 0.

## scenario3_insider_modbus
Records in scope: 21 | attack records: 8

| Metric | Baseline | Improved |
|---|---|---|
| Correlation precision | 0.40 | 1.00 |
| Correlation recall | 1.00 | 1.00 |
| Correlation F1 | 0.57 | 1.00 |
| Stage accuracy | 1.00 | 1.00 |
| Timeline sequence similarity | 0.67 | 1.00 |
| Compromised-asset F1 | 1.00 | 1.00 |
| RCA initial vector correct | YES | YES |
| RCA entry IP correct | NO | YES |
| RCA origin type correct | NO | YES |

False positives kept: baseline 12, improved 0. Missed attack records: baseline 0, improved 0.

## scenario4_c2_beacon_dnp3
Records in scope: 47 | attack records: 13

| Metric | Baseline | Improved |
|---|---|---|
| Correlation precision | 0.28 | 1.00 |
| Correlation recall | 1.00 | 1.00 |
| Correlation F1 | 0.43 | 1.00 |
| Stage accuracy | 0.38 | 1.00 |
| Timeline sequence similarity | 0.24 | 1.00 |
| Compromised-asset F1 | 0.80 | 1.00 |
| RCA initial vector correct | NO | YES |
| RCA entry IP correct | NO | YES |
| RCA origin type correct | NO | YES |

False positives kept: baseline 34, improved 0. Missed attack records: baseline 0, improved 0.

## Macro average

| Metric | Baseline | Improved |
|---|---|---|
| Correlation precision | 0.36 | 1.00 |
| Correlation recall | 1.00 | 1.00 |
| Correlation F1 | 0.53 | 1.00 |
| Stage accuracy | 0.64 | 1.00 |
| Timeline sequence similarity | 0.47 | 1.00 |
| Compromised-asset F1 | 0.70 | 1.00 |
| RCA initial vector correct | 1/4 | 4/4 |
| RCA entry IP correct | 2/4 | 4/4 |
| RCA origin type correct | 0/4 | 4/4 |
## Time-window sensitivity

| Window (min) | Improved precision | Improved recall | Improved F1 | Baseline F1 |
|---|---|---|---|---|
| 1 | 1.00 | 1.00 | 1.00 | 0.53 |
| 2 | 1.00 | 1.00 | 1.00 | 0.53 |
| 3 | 1.00 | 1.00 | 1.00 | 0.53 |
| 5 | 1.00 | 1.00 | 1.00 | 0.53 |
| 10 | 1.00 | 1.00 | 1.00 | 0.53 |
| 15 | 1.00 | 1.00 | 1.00 | 0.53 |
| 30 | 1.00 | 1.00 | 1.00 | 0.53 |

## Important limitations

- All three scenarios are synthetic and were written by the same author as the pipeline, and the improved stage tables were tuned while developing against them. These numbers show that the pipeline logic works on designed scenarios; they are NOT proof of generalisation.
- Stage mapping tables (IDS category / device event type) cover the vocabulary of these scenarios; unseen vocabulary falls back to keyword matching.
- Known hard cases are kept on purpose (a legitimate failed login on an attacker-touched host is still reported as relevant), so precision stays below 1.0.
- A compromised host that also carries legitimate traffic cannot be separated by these rules alone; baselining known-good flows is future work.
