"""Exercise archived policy evidence through the deployed dashboard's History API."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def lookup(h, start, end, **filters):
    params = dict(start=start.isoformat(), end=end.isoformat(), **filters)
    result = h.api('history?' + urlencode(params))
    assert result['status']['enabled'], 'The dashboard has no Loki endpoint'
    return result['rows']


def replay_yesterday(h, record, day_start):
    # Use the record exported by the live server. Shift only its clock, keeping
    # the interval length and every field used for attribution intact.
    at = day_start + timedelta(hours=12)
    row = dict(record, at=at.strftime('%Y-%m-%dT%H:%M:%SZ'))
    if record.get('start'):
        duration = datetime.fromisoformat(record['at']) - datetime.fromisoformat(record['start'])
        start = at - duration
        row['start'] = start.strftime('%Y-%m-%dT%H:%M:%S.%f').rstrip('0').rstrip('.') + 'Z'
    cluster = h.get('-n', 'ovn-light', 'configmap', 'ovn-light-history')['data']['OVN_LIGHT_LOKI_CLUSTER']
    # Loki enforces an out-of-order window per stream. Isolate the replay
    # from today's live writes while keeping it visible to this cluster's API.
    labels = dict(job='ovn-light', cluster=cluster, verdict='drop', fixture='yesterday')
    values = [[str(int(at.timestamp()) * 10**9), json.dumps(row)]]
    push = json.dumps({'streams': [{'stream': labels, 'values': values}]}).encode()
    req = Request(h.args.loki_url + '/loki/api/v1/push', data=push,
                  headers={'Content-Type': 'application/json'})
    with urlopen(req, timeout=15) as response:
        assert response.status == 204, response.status
    # Yesterday's queries can skip the ingester. Publish its chunks before reading.
    with urlopen(Request(h.args.loki_url + '/flush', data=b''), timeout=30) as response:
        assert 200 <= response.status < 300, response.status
    return row


def check_history(h):
    h.setup(same_node=True)
    h.eventually(lambda: h.connection(h.source, h.dest, True))
    policy = h.admin_policy('AdminNetworkPolicy')
    name = policy['metadata']['name']
    since = datetime.now(timezone.utc)
    filters = dict(verdict='drop', network=h.dest['network'], search=name)
    h.apply(policy)
    try:
        def live_drop():
            h.connection(h.source, h.dest, False)
            h.api('refresh', {})
            rows = lookup(h, since, datetime.now(timezone.utc), **filters)
            for row in rows:
                if (row['verdict'] != 'drop' or row['network'] != h.dest['network'] or
                        row['destination'].get('uid') != h.dest['uid'] or row['source'].get('uid') != h.source['uid']):
                    continue
                for c in row.get('causes', []):
                    if (c['kind'] == 'AdminNetworkPolicy' and c.get('name') == name and
                            c.get('ruleName') == 'block-client' and c.get('rule') == '0' and
                            c.get('direction') == 'Ingress' and c['action'] == 'drop' and c['acl']):
                        return row
            raise AssertionError(f'No archived drop with the test pod UIDs and {name}/block-client ({len(rows)} rows)')
        live = h.eventually(live_drop, timeout=180)
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday = today - timedelta(days=1)
        replay = replay_yesterday(h, live, yesterday)
    finally:
        h.checked('delete', 'adminnetworkpolicy', name)
    h.eventually(lambda: h.connection(h.source, h.dest, True))
    h.eventually(lambda: h.api('refresh', {}))

    def historical_drop():
        rows = lookup(h, yesterday, today, **filters)
        for row in rows:
            if row == replay:
                return row
        raise AssertionError('Yesterday did not return the original counter and policy evidence')

    archived = h.eventually(historical_drop)
    assert not lookup(h, yesterday, yesterday + timedelta(hours=1), **filters), 'Time filter leaked'
    for field, value in [('verdict', 'forward'), ('network', 'missing-network'), ('search', 'missing-policy')]:
        assert not lookup(h, yesterday, today, **(filters | {field: value})), f'{field} filter leaked'
    if h.args.artifacts:
        (Path(h.args.artifacts) / 'yesterday-drop.json').write_text(json.dumps(archived, indent=2) + '\n')
    print(f"Yesterday: {h.source['pod']} → {h.dest['pod']}, AdminNetworkPolicy {name}, ingress rule 0 "
          f"(block-client). Archived evidence survived policy deletion and restored TCP connectivity.", flush=True)
