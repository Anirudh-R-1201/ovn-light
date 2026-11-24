/* SPDX-License-Identifier: Apache-2.0 */
'use strict';

let historyRequest = 0;
function historyRange(now) {
  const period = $('history-window').value;
  if (period === 'custom') return [new Date($('history-start').value), new Date($('history-end').value)];
  if (period === 'yesterday') {
    const end = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const start = new Date(end);
    start.setDate(start.getDate() - 1);
    return [start, end];
  }
  return [new Date(now.getTime() - (period === 'day' ? 24 : 1) * 3600000), now];
}

function historicalPolicy(c) {
  if (c.kind === 'NetpolNamespace') {
    const names = (c.selecting || []).join(', ');
    return `Namespace default deny · ${c.namespace || 'unresolved namespace'} · ${c.direction || 'unknown direction'}` +
      (names ? ` · Selecting policies: ${names}` : '') + (c.selectionIncomplete ? ' · Partial policy inventory' : '');
  }
  const name = [c.namespace, c.name].filter(Boolean).join('/');
  const rule = c.rule === undefined ? '' : ' · rule ' + c.rule;
  return [c.kind || 'OVN ACL', name, c.direction].filter(Boolean).join(' ') + rule + (c.ruleName ? ' (' + c.ruleName + ')' : '');
}

function historyRow(r) {
  const item = text('details', '', 'record');
  const summary = text('summary', '', 'history-row');
  const at = new Date(r.at).toLocaleString();
  const transport = [r.protocol, r.destination.port].filter(Boolean).join('/');
  summary.append(text('time', at), badge(r.counterScope === 'branch-input' ? 'Branch input' : r.verdict, r.verdict === 'drop' ? 'red' : r.counterScope === 'branch-input' ? '' : 'green'),
    text('strong', `${endpoint(r.source)} → ${endpoint(r.destination)}${transport ? ' · ' + transport : ''}`));
  const causes = list(r.causes);
  if (r.verdict === 'drop') summary.append(text('span', (causes.length > 1 ? 'Possible blocking ACLs · ' : '') + causes.map(historicalPolicy).join(' / ') || 'Policy attribution unavailable', 'history-policy'));
  item.append(summary);
  const delta = r.packetDelta === undefined ? `${count(r.cachedPackets)} cached packets · Activity interval unknown`
    : `+${count(r.packetDelta)} packets${r.byteDelta === undefined ? '' : ' · +' + count(r.byteDelta) + ' bytes'}`;
  item.append(text('p', [r.network || 'Unresolved network', r.node, r.location, delta].filter(Boolean).join(' · ')));
  if (r.source.ip || r.destination.ip) item.append(text('p', (r.source.ip || 'Unknown source IP') + ' → ' + (r.destination.ip || 'Unknown destination IP')));
  if (r.counterScope === 'branch-input') item.append(text('p', 'The counter measures packets entering a conditional output. Forwarding on this branch is unconfirmed.'));
  if (r.start) item.append(text('p', 'Counter interval from ' + new Date(r.start).toLocaleString() + ' to ' + at));
  if (r.shared) item.append(text('p', 'Shared counter. Multiple paths can reference this count.'));
  if (r.partial) item.append(text('p', 'Partial datapath evidence.'));
  for (const c of causes) {
    if (c.kind === 'NetpolNamespace') item.append(text('p', 'The ACL identifies namespace isolation. The listed policies selected this pod and direction at collection time. The ACL alone cannot identify a single responsible policy.'));
    if (c.ruleName) item.append(text('p', 'The rule name comes from the policy inventory at collection time. Cached ACLs can reflect an earlier rule version.'));
    item.append(text('pre', [c.action, c.acl, c.match].filter(Boolean).join('\n')));
  }
  return item;
}

async function loadHistory() {
  const request = ++historyRequest;
  const status = $('history-status'), results = $('history-results');
  const [start, end] = historyRange(new Date());
  results.replaceChildren();
  if (!Number.isFinite(+start) || !Number.isFinite(+end) || end <= start) {
    status.textContent = 'Choose a start time before the end time.';
    return;
  }
  $('history-network-list').replaceChildren(...list(state.networks).map(n => new Option(n.name, n.id)));
  const q = new URLSearchParams({start:start.toISOString(), end:end.toISOString(), verdict:$('history-verdict').value,
    network:$('history-network').value.trim(), search:$('history-search').value.trim()});
  status.textContent = 'Searching history…';
  try {
    const data = await api('history?' + q);
    if (request !== historyRequest || currentPage !== 'history') return;
    if (!data.status.enabled) {
      status.textContent = 'Traffic history is disabled. Configure a Loki endpoint on the OVN-Light server to start recording.';
      return;
    }
    const range = start.toLocaleString() + ' – ' + end.toLocaleString();
    let message = data.more ? 'Showing the newest 100 matches. Narrow the time range or filters for more detail.' :
      data.rows.length ? `${data.rows.length} recorded observation${data.rows.length === 1 ? '' : 's'}.` : 'No recorded observations match this search. History starts when export is enabled.';
    if (data.status.omitted) message += ` Export gaps since server startup: ${count(data.status.omitted)} observations.`;
    if (data.status.lastError) message += ' Export error: ' + data.status.lastError;
    status.textContent = range + ' · ' + message;
    results.replaceChildren(...data.rows.map(historyRow));
  } catch (err) {
    if (request === historyRequest) status.textContent = 'History query failed. ' + err.message;
  }
}
$('history-form').onsubmit = event => { event.preventDefault(); loadHistory(); };
$('history-window').onchange = () => {
  $('history-custom').classList.toggle('hidden', $('history-window').value !== 'custom');
  if ($('history-window').value !== 'custom') loadHistory();
};
$('history-verdict').onchange = loadHistory;
