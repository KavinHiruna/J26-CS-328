# Public dataset test (Edge-IIoTset training split)

Records: 126240 read, 12512 skipped (no usable time), 113728 used, 94287 labelled attack.
Seed IP: 192.168.0.170 (most frequent sources in Component 1 alerts: [('192.168.0.128', 7614), ('192.168.0.170', 4320), ('0.0.0.0', 3)]).

| Method | TP | FP | FN | Precision | Recall | F1 | Benign excluded |
|---|---|---|---|---|---|---|---|
| Everything in the window | 94287 | 19441 | 0 | 0.829 | 1.000 | 0.907 | 0.000 |
| Records touching the seed IP | 71869 | 0 | 22418 | 1.000 | 0.762 | 0.865 | 1.000 |
| Seeded correlation (this work) | 77552 | 8061 | 16735 | 0.906 | 0.823 | 0.862 | 0.585 |

Run time: load 1.94 s, correlation 0.32 s for 113728 records.

Missed attack records by reason: no IP address in the record: 2357; 0.0.0.0 -> 224.0.0.1: 124; 172.217.19.42 -> 192.168.0.128: 16; 104.16.87.20 -> 192.168.0.128: 6; 142.250.200.205 -> 192.168.0.128: 5; 172.217.19.35 -> 192.168.0.128: 2; 57.72.100.117 -> 192.168.0.128: 2; 227.18.6.241 -> 192.168.0.128: 1

Benign records kept, by address pair: 192.168.0.128 -> 192.168.0.101: 8032; 192.168.0.128 -> 192.168.0.1: 17; 192.168.0.128 -> 224.0.0.251: 10; 192.168.0.128 -> 94.228.220.14: 1; 192.168.0.128 -> 196.200.160.123: 1
