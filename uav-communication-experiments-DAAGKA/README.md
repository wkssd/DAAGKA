# DAAGKA: Decentralized Anonymous Asynchronous Group Key Agreement with Unstable Links for UANET

This repository contains the **DAAGKA** reference implementation and **NS-3** simulation suite that accompanies our paper:

- **Decentralized Anonymous Asynchronous Group Key Agreement with Unstable Links for UANET**

## Abstract

With the rapid development of Unmanned Aerial Vehicle (UAV) technology, UAVs can form an Ad-Hoc network when performing tasks, called UAV Ad-Hoc Networks (UANET). In this process, group key agreement is often employed to ensure secure communication. However, the instability of wireless communications, combined with the rapid movements of UAVs and the complexity of the flight environment, often results in the ineffectiveness of traditional group key agreement methods. In recent years, asynchronous group key agreement protocols have been extensively studied, providing a possible solution to this problem. However, existing works rely on a third-party server or a group administrator, which does not match the decentralized architecture of UANET. Moreover, these works do not take into account member anonymity, thereby posing risks to the communication security within UANETs. To address the above issues, we first propose an anonymous authenticated ephemeral key generation and uploading method to protect the anonymity of group members and ensure mutual authentication. Then, we design a decentralized and asynchronous group key agreement protocol to avoid dependence on third-party servers and efficiently generate the group key. The security of the protocol is proved under the random oracle model. We evaluate the performance of the proposed scheme in both real-world environments and NS3 simulation environments. The reported experiments characterize agreement and update delays in physical and simulated UANET settings, as well as local computation and energy costs on embedded hardware.

Source files are at the repository root.

## Repository layout

```text
.
├─ raft.h                      # Raft consensus
├─ wire.h                      # Message encoding and fragmentation
├─ append-pacer.h              # Pacing of Append RPCs
├─ daagka-crypto.h             # Group key agreement cryptography
├─ ns3-peer.h                  # UAV node, network, and protocol adapter
├─ ns3-gka.cc                  # NS-3 simulation entry
├─ core-test.cc                # Raft consensus test
├─ wire-test.cc                # Message codec and fragmentation test
├─ pacer-test.cc               # Append pacer test
├─ daagka-crypto-test.cc       # Group key agreement test
├─ build-ns3.py                # NS-3 program build
└─ paper-model-experiment.py   # Paper-shaped NS-3 experiment driver
```

## Dependencies

- **ns-3**: 3.25
- **Compiler**: `g++`
- **OpenSSL**: `libcrypto`
- **Python**: 3.5 or later

## How to run

Run the commands from `uav-communication-experiments-dev`.

### Raft

```bash
g++ -std=c++11 -O2 -Wall -Wextra -Werror raft-core/core-test.cc -o /tmp/raft-test
/tmp/raft-test

python3 raft-core/build-ns3.py /tmp/iot-ns3-gka
/tmp/iot-ns3-gka --n=<number-of-nodes> --seed=17 --rngRun=1 --durationMs=10000 --out=/tmp/raft-run
```

`--n` is an integer from 3 to 50.

### Group key agreement

```bash
g++ -std=c++11 -O2 -Wall -Wextra -Werror raft-core/daagka-crypto-test.cc -lcrypto -o /tmp/gka-test
/tmp/gka-test

/tmp/iot-ns3-gka --n=<number-of-nodes> --coreNodes=<number-of-core-nodes> --stagedAgreement=1 --cryptoAgreement=1 \
  --seed=17 --rngRun=1 --computeMs=0 --durationMs=10000 --out=/tmp/gka-run
```

`--n` is an integer from 3 to 50, and `--coreNodes` is an integer from 3 to `--n`.

## Simulation parameters

| Parameter | Value |
|---|---|
| Simulation area | 100 m × 100 m × 100 m by default; configurable through `--distance` and `--height` |
| Mobility model | Gauss–Markov by default; constant position is optional |
| Propagation model | Friis + Nakagami + log-normal shadowing + range |
| Communication standard | IEEE 802.11b |
| PHY rate | DSSS 5.5 Mbps |
| Flight speed | 5 m/s by default; configurable from 0 to 100 m/s |
| Carrier frequency | 2.4 GHz |
| Transmission power | 20 dBm |
| Shadowing | Normal distribution, mean 0 dB, variance 16 dB² |
| Maximum transmission range | Diagonal of the simulation area |
| Rx noise figure / Rx gain | NS-3 defaults, 7 dB / 1 dB |
| MAC | Ad hoc |

## Outputs

- **Raft and group key agreement simulations**: `summary.txt`, `events.csv`, and `config.txt` in the result directory.
- **Tests**: pass or failure messages on standard output.
