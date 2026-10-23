# Public dataset test (Edge-IIoTset training split)

Records: 126240 read, 12512 skipped (no usable time), 113728 used, 94287 labelled attack.
Seed IP: 192.168.0.170 (most frequent sources in Component 1 alerts: [('192.168.0.128', 7614), ('192.168.0.170', 4320), ('0.0.0.0', 3)]).

| Method | TP | FP | FN | Precision | Recall | F1 | Benign excluded |
|---|---|---|---|---|---|---|---|
| Everything in the window | 94287 | 19441 | 0 | 0.829 | 1.000 | 0.907 | 0.000 |
| Records touching the seed IP | 71869 | 0 | 22418 | 1.000 | 0.762 | 0.865 | 1.000 |
| Seeded correlation (this work) | 77552 | 8061 | 16735 | 0.906 | 0.823 | 0.862 | 0.585 |

Run time: load 2.11 s, correlation 0.23 s for 113728 records.

Missed attack records by reason: inbound to the victim from many other source addresses (distributed or spoofed): 14254; no IP address in the record (ARP, ICMP or malformed): 2357; other: 124 (14228 distinct other source addresses)

Benign records kept, by address pair: 192.168.0.128 -> 192.168.0.101: 8032; 192.168.0.128 -> 192.168.0.1: 17; 192.168.0.128 -> 224.0.0.251: 10; 192.168.0.128 -> 94.228.220.14: 1; 192.168.0.128 -> 196.200.160.123: 1
