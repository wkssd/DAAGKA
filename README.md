# Decentralized Anonymous Asynchronous Group Key Agreement with Unstable Links for UANET

Zhan Zhang, Xinghua Li, Yinbin Miao, Zhe Ren, Yunwei Wang, and Robert H. Deng

## Description

This repository implements the asynchronous group key agreement stage of **DAAGKA** in ns-3. With the rapid development of Unmanned Aerial Vehicle (UAV) technology, UAVs can form an Ad-Hoc network when performing tasks, called UAV Ad-Hoc Networks (UANET). In this process, group key agreement is often employed to ensure secure communication. However, the instability of wireless communications, combined with the rapid movements of UAVs and the complexity of the flight environment, often results in the ineffectiveness of traditional group key agreement methods. In recent years, asynchronous group key agreement protocols have been extensively studied, providing a possible solution to this problem. However, existing works rely on a third-party server or a group administrator, which does not match the decentralized architecture of UANET. Moreover, these works do not take into account member anonymity, thereby posing risks to the communication security within UANETs. To address the above issues, we first propose an anonymous authenticated ephemeral key generation and uploading method to protect the anonymity of group members and ensure mutual authentication. Then, we design a decentralized and asynchronous group key agreement protocol to avoid dependence on third-party servers and efficiently generate the group key. 


## Repository Layout

```text
DAAGKA/
├── README.md
├── raft-core/
│   └── raft.h             # Raft election, replication, and commitment
├── uav-node/
│   ├── ns3-peer.h         # UAV node and two-stage GKA workflow
│   ├── crypto.h           # Cryptographic interfaces
│   ├── crypto.cc          # OpenSSL-based implementation
│   ├── wire.h             # Message encoding and fragmentation
│   └── append-pacer.h     # Optional message pacing
└── simulation/
    ├── ns3-gka.cc         # Network setup and simulation entry
    └── ns3-fault.h        # Disconnection and reconnection model
```

## Dependencies

- Linux
- ns-3 3.25
- g++ 7.5.0 / C++11
- Python 3.5+
- OpenSSL 1.0.2g 

## How to run?

Install NS-3 (v3.25) on a Linux machine. Follow the official [ns-3 build guide](https://www.nsnam.org/docs/release/3.25/) or use your package manager.

Clone or move the repository into the scratch folder.

```text
/home/<user>/workspace/ns-3.25/scratch/DAAGKA
```

Build and run one scenario from the ns-3 root.

```bash
cd ns-3.25
./waf --run "DAAGKA --n=5"
```

`--n` is the UAV count, from 3 to 50. Omitting it runs with 3 UAVs. A run writes `DAAGKA-n5/summary.txt` for `--n=5` and refuses to overwrite an existing directory.

## NS-3 Simulation Parameters


| Parameter | Value |
|---|---|
| UAV count | 3–50 |
| Area size | 400 × 400 × 100 m³ |
| Flight speed | 0–20 m/s |
| Communication standard | IEEE 802.11b |
| Routing | OLSR |
| Data rate | 5.5 Mbit/s |
| Transmit power | 20 dBm |
| Channel model | Friis, Nakagami, log-normal shadowing, and range limit |
| Mobility model | Gauss–Markov |
| Simulation duration | 60 s |


