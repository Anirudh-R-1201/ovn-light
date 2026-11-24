/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const testDialog = $('traffic-test-dialog');
let testTimer, testSequence = 0, testEnabled = false, testRunning = false, testContext = '';

function updateTestForm() {
  const src = $('traffic-test-source').value, dst = $('traffic-test-destination').value;
  const reason = testContext || (!testEnabled ? 'Traffic tests require a live, write-enabled server with the test runner installed.' :
    testRunning ? 'One test is running. You can close this dialog and return to its result.' :
    !src || !dst || src === dst ? 'Select two distinct nodes.' : '');
  $('traffic-test-message').textContent = reason;
  $('traffic-test-submit').disabled = Boolean(reason);
}

function testResult(run) {
  const root = $('traffic-test-result');
  root.replaceChildren();
  if (!run) return;
  root.append(text('h3',run.finished ? 'Last test' : 'Current test'), text('p',run.source.node+' → '+run.destination.node+' · '+new Date(run.started).toLocaleString()));
  const traffic = run.traffic;
  if (traffic?.delivered) root.append(text('strong','TCP delivered'),text('p',count(traffic.bytes)+' bytes received · '+(traffic.bps/1e6).toFixed(2)+' Mbit/s'));
  else if (traffic) root.append(text('strong','TCP test failed'),text('p',traffic.error || 'No completed transfer.'));
  else root.append(text('p','Test in progress. Waiting for the runner and collector samples.'));
  if (run.drop) root.append(text('p','Matching policy drop · '+run.drop));
  for (const n of run.nodes) {
    const card = text('section','','record');
    const endpoint = n.node === run.source.node ? run.source : run.destination;
    card.append(text('strong',n.node),text('p', [endpoint.pod,endpoint.ip].filter(Boolean).join(' · ')));
    if (n.state === 'disabled') card.append(text('p','Hardware offload disabled'));
    else if (!n.paths?.length) card.append(text('p',run.finished ? 'Offload inconclusive. No active path matched the test data stream.' : 'Awaiting matching datapath evidence.'));
    for (const p of n.paths || []) {
      const detail=text('details','');
      detail.append(text('summary',(offloadLabels[p.status] || p.status)+' · '+(p.tuple.sourcePort === '35201' ? 'client → server' : 'server → client')+(p.issue?' · persistent issue':'')),
        text('p',p.summary+' · '+new Date(p.observedAt).toLocaleTimeString()));
      for (const s of p.stages || []) {
        detail.append(text('p','recirc '+s.recirc+' · '+s.inPort+' · '+s.status+' · partial packets '+(s.partialDelta == null?'Δ unavailable':'+'+count(s.partialDelta))+(s.reason?' · '+s.reason:'')));
      }
      for (const c of p.conntrack || []) detail.append(text('p','CT zone '+c.zone+' · '+(c.direction||'direction unknown')+' · '+c.status+' · original '+(c.original||'unknown')+' · reply '+(c.reply||'unknown')+(c.reason?' · '+c.reason:'')));
      for (const warning of p.warnings || []) detail.append(text('p',warning,'note'));
      card.append(detail);
    }
    if (n.limited) card.append(text('p','Additional evidence exceeded the result limit.','note'));
    root.append(card);
  }
}

async function refreshTest(seq) {
  try {
    const status=await api('traffic-test');
    if (seq!==testSequence || !testDialog.open) return;
    testEnabled=status.enabled;
    testRunning=Boolean(status.run && !status.run.finished);
    updateTestForm();testResult(status.run);
    if (testRunning) testTimer=setTimeout(()=>refreshTest(seq),4000);
  } catch (e) {
    if(seq===testSequence) $('traffic-test-message').textContent=e.message;
  }
}
function openTrafficTest(src,dst,network) {
  const names=list(state.nodes).map(n=>n.name);
  for (const id of ['traffic-test-source','traffic-test-destination']) $(id).replaceChildren(...names.map(n=>new Option(n,n)));
  $('traffic-test-source').value=src || names[0] || '';
  $('traffic-test-destination').value=dst || names.find(n=>n!==$('traffic-test-source').value) || '';
  testContext=network && network!=='default' ? 'This test supports the default network. The selected link uses '+network+'.' : '';
  clearTimeout(testTimer);testEnabled=false;testRunning=false;
  $('traffic-test-result').replaceChildren();$('traffic-test-submit').disabled=true;
  $('traffic-test-message').textContent='Checking runner…';testDialog.showModal();refreshTest(++testSequence);
}
$('offload-run-test').onclick=()=>openTrafficTest($('offload-node').value,'',$('offload-network').value);
$('traffic-test-source').onchange=updateTestForm;
$('traffic-test-destination').onchange=updateTestForm;
testDialog.addEventListener('close',()=>{clearTimeout(testTimer);testSequence++});
$('traffic-test-form').onsubmit=async e=>{
  e.preventDefault();if ($('traffic-test-submit').disabled)return;
  $('traffic-test-submit').disabled=true;
  const seq=++testSequence;
  try {
    const status=await api('traffic-test',{sourceNode:$('traffic-test-source').value,destinationNode:$('traffic-test-destination').value,network:'default'});
    if(seq!==testSequence)return;
    testRunning=true;updateTestForm();testResult(status.run);refreshTest(seq);
  } catch(err) {
    if(seq===testSequence){updateTestForm();$('traffic-test-message').textContent=err.message}
  }
};
