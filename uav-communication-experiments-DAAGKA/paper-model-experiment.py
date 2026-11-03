#!/usr/bin/env python3
"""Run paper-shaped two-commit NS-3 experiments, optionally with P-256 prototype.

The protocol model is not an authenticated DAAGKA deployment or physical-UAV result.
"""
import argparse
import csv
import json
import statistics
import subprocess
from pathlib import Path


def read_fields(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)


def timeline(path):
    with path.open(newline='') as stream:
        events = list(csv.DictReader(stream))
    selection = [e for e in events if e['event'] == 'majority_commit' and e['request'] == 'gka-selection-1']
    material = [e for e in events if e['event'] == 'majority_commit' and e['request'] == 'gka-single-1']
    observations = [e for e in events if e['event'] == 'selection_observed']
    if len(selection) != 1 or len(material) != 1 or not observations:
        return selection, material, observations, None
    first = int(selection[0]['time_ns'])
    last = int(material[0]['time_ns'])
    if first > last or int(observations[0]['time_ns']) < first:
        raise ValueError('selection/material ordering violation: %s' % path)
    return selection, material, observations, (last - first) / 1e6


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--metric', choices=('consensus', 'agreement'), required=True)
    parser.add_argument('--core-nodes', type=int, required=True, help='fixed voting core UAVs; 3 <= m <= smallest n')
    parser.add_argument('--seeds', type=int, default=10)
    parser.add_argument('--duration-ms', type=int, default=30000)
    parser.add_argument('--loss', type=float, default=0.0)
    parser.add_argument('--crypto', action='store_true', help='enable P-256 prototype; authorization/ledger remain modeled')
    args = parser.parse_args()
    counts = list(range(20, 41, 2)) if args.metric == 'consensus' else list(range(20, 31, 2))
    if not (3 <= args.core_nodes <= counts[0]) or args.seeds < 1 or args.duration_ms < 1000:
        parser.error('invalid voters, seed count or deadline')
    if not args.binary.is_file():
        parser.error('missing binary')
    args.out.mkdir(parents=True, exist_ok=False)
    records = []
    for n in counts:
        for seed in range(1, args.seeds + 1):
            run = args.out / ('n%d-seed%02d' % (n, seed))
            cmd = [str(args.binary.resolve()), '--n=%d' % n,
                   '--coreNodes=%d' % args.core_nodes, '--stagedAgreement=1', '--olsr=1',
                   '--cryptoAgreement=%d' % args.crypto,
                   '--seed=%d' % seed, '--rngRun=1', '--p=%s' % args.loss,
                   '--distance=400', '--height=100', '--speed=5', '--alpha=0.85',
                   '--gmStepMs=500', '--initiator=0',
                   '--computeMs=%d' % (0 if args.crypto else 10), '--startMs=100', '--retryMs=200',
                   '--durationMs=%d' % args.duration_ms, '--out=%s' % run]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True)
            if proc.returncode not in (0, 2):
                raise RuntimeError('%s: %s' % (run, proc.stderr or proc.stdout))
            cfg = read_fields(run / 'config.txt')
            expected_model = 'p256-prototype-no-registration' if args.crypto else 'synthetic-noncryptographic'
            if cfg['protocolModel'] != expected_model or cfg['routing'] != 'OLSR' or \
                    cfg['coreNodes'] != str(args.core_nodes) or cfg['stagedAgreement'] != '1':
                raise ValueError('unexpected simulation configuration: %s' % run)
            summary = read_fields(run / 'summary.txt')
            selected, material, observed, gap = timeline(run / 'events.csv')
            if (proc.returncode == 0) != (summary['status'] == 'confirmed'):
                raise ValueError('exit/status mismatch: %s' % run)
            if summary['status'] == 'confirmed' and (gap is None or not summary['online_latency_ms']):
                raise ValueError('confirmed without both majority commits: %s' % run)
            if args.crypto and summary['status'] == 'confirmed' and not summary['crypto_recover_cpu_us']:
                raise ValueError('crypto confirmation without verified group key: %s' % run)
            records.append(dict(n=n, core_nodes=args.core_nodes, seed=seed,
                                status=summary['status'], selection_commits=len(selected),
                                material_commits=len(material), selection_observed=len(observed),
                                two_commit_gap_ms=gap if gap is not None else '',
                                online_latency_ms=summary['online_latency_ms'],
                                crypto_issue_cpu_us=summary.get('crypto_issue_cpu_us', ''),
                                crypto_recover_cpu_us=summary.get('crypto_recover_cpu_us', ''), run=run.name))
            print('n=%d seed=%d status=%s selection=%d material=%d' %
                  (n, seed, summary['status'], len(selected), len(material)), flush=True)
    with (args.out / 'trials.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    groups = []
    for n in counts:
        samples = [r for r in records if r['n'] == n]
        committed = [r['two_commit_gap_ms'] for r in samples if r['two_commit_gap_ms'] != '']
        online = [float(r['online_latency_ms']) for r in samples if r['status'] == 'confirmed']
        groups.append(dict(n=n, trials=len(samples), both_committed=len(committed),
                           confirmed=len(online), mean_two_commit_gap_ms=statistics.mean(committed) if committed else '',
                           mean_online_latency_ms=statistics.mean(online) if online else ''))
    with (args.out / 'summary.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(groups[0]))
        writer.writeheader()
        writer.writerows(groups)
    (args.out / 'method.json').write_text(json.dumps(dict(
        source='NS-3 P-256 prototype with modeled registration/ledger' if args.crypto else
               'NS-3 synthetic noncryptographic two-stage agreement',
        metric=args.metric, n_values=counts, core_voters=args.core_nodes, seeds=args.seeds, crypto=args.crypto,
        command_example=cmd, definition='two_commit_gap: first selection majority_commit to material majority_commit; online_latency: initiator local_read to confirmed material',
        limitations=('Prototype uses real P-256 Schnorr/ECDH/AES-GCM but preprovisions roster in-process; no authenticated registration, persistent consortium ledger, offline retrieval, membership change, Raspberry Pi or energy measurement. The initiator alone verifies its key in NS-3. CPU microseconds are host time and are not part of ns-3 virtual time.' if args.crypto else
                     'Synthetic payloads only; no ECC, authentication, offline recovery, membership change, Raspberry Pi or energy measurement. No delay is assigned to timed-out runs.')
    ), indent=2) + '\n')


if __name__ == '__main__':
    main()
