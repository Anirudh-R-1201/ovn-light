#!/usr/bin/env python3
"""Keep workstation KIND tests small; hosted CI uses separate disposable runners."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

GIB = 1024 ** 3
NODE_MEMORY = 4 * GIB
MAX_NODES = 2


def docker(*args):
    return subprocess.run(['docker', *args], check=True, text=True,
                          capture_output=True).stdout.strip()


def require_memory(minimum):
    fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available = int(fields['MemAvailable'].split()[0]) * 1024
    if available < minimum:
        raise RuntimeError(f'Only {available / GIB:.1f} GiB available; need {minimum / GIB:g} GiB for this local operation.')


def check_create():
    # Stopped clusters still have reusable state. Do not accumulate another copy.
    nodes = docker('ps', '-a', '--filter', 'label=io.x-k8s.kind.cluster',
                   '--format', '{{.Names}}')
    if nodes:
        raise RuntimeError('Local KIND nodes already exist. Reuse the intended cluster instead of creating another:\n' + nodes)
    require_memory(12 * GIB)


def limit_cluster(cluster):
    require_memory(4 * GIB)
    ids = docker('ps', '-aq', '--filter', 'label=io.x-k8s.kind.cluster=' + cluster).split()
    if not 1 <= len(ids) <= MAX_NODES:
        raise RuntimeError(f'Local demo must have 1–{MAX_NODES} nodes; {cluster} has {len(ids)}. No limits changed.')
    nodes = json.loads(docker('inspect', *ids))
    for node in nodes:
        if node['Config']['Labels'].get('io.x-k8s.kind.cluster') != cluster:
            raise RuntimeError('Cluster identity changed; no limits changed.')
    for node in nodes:
        current = node['HostConfig']['Memory']
        limit = min(current, NODE_MEMORY) if current > 0 else NODE_MEMORY
        # Equal memory and memory-swap values prohibit extra container swap.
        docker('update', '--memory=' + str(limit), '--memory-swap=' + str(limit), node['Id'])
    print(f'{cluster}: at most {MAX_NODES} nodes, at most 4 GiB per node, no extra swap.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['check-create', 'limit'])
    parser.add_argument('cluster', nargs='?')
    args = parser.parse_args()
    if args.operation == 'limit' and not args.cluster:
        parser.error('limit requires a cluster name')
    if os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted':
        return
    try:
        if args.operation == 'check-create':
            check_create()
        else:
            limit_cluster(args.cluster)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        detail = error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error)
        print('Local KIND budget: ' + detail, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
