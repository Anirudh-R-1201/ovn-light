/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const testDialog = $('traffic-test-dialog');
let testTimer, testSequence = 0, testEnabled = false, testRunning = false, testContext = '';

let catalog, testSubmitting = false;
const testProfile = () => catalog?.profiles.find(p=>p.id===$('traffic-test-profile').value);
const testCase = () => catalog?.cases.find(c=>c.id===$('traffic-test-case').value);

function fillTestChoices(id, choices, previous) {
  const el=$(id);
  el.replaceChildren(...choices.map(c=>new Option(c.name,c.id)));
  if(choices.some(c=>c.id===previous)) el.value=previous;
}

function selectTestProfile(previousCase,src,dst) {
  const profile=testProfile();
  if(!profile)return;
  const choices=catalog.cases.filter(c=>!c.service || profile.service);
  const old=catalog.cases.find(c=>c.id===previousCase);
  const fallback=choices.find(c=>c.sameNode===Boolean(old?.sameNode))?.id;
  fillTestChoices('traffic-test-case',choices,choices.some(c=>c.id===previousCase)?previousCase:fallback);
  $('traffic-test-description').textContent=profile.description;
  selectTestNodes(src,dst);
}

function selectTestNodes(src,dst) {
  const test=testCase(), profile=testProfile();
  if(!test||!profile)return;
  const device=profile.rdma?catalog.rdmaResource:catalog.device;
  const eligible=catalog.nodes.filter(n=>!device || (profile.rdma?n.rdmaDevices:n.devices)>=(test.sameNode?2:1));
  const choices=eligible.map(n=>({id:n.name,name:n.name}));
  fillTestChoices('traffic-test-source',choices,src);
  updateTestDestination(dst);
}

function updateTestDestination(dst) {
  const src=$('traffic-test-source').value;
  const single=testCase()?.sameNode;
  const choices=Array.from($('traffic-test-source').options).filter(n=>single?n.value===src:n.value!==src)
    .map(n=>({id:n.value,name:n.textContent}));
  fillTestChoices('traffic-test-destination',choices,dst);
  $('traffic-test-destination').disabled=Boolean(single);
  updateTestForm();
}

function updateTestForm() {
  const src = $('traffic-test-source').value, dst = $('traffic-test-destination').value;
  const reason = testContext || (!testEnabled ? 'Traffic tests require a live, write-enabled server with the test runner installed.' :
    testRunning ? 'One test is running. You can close this dialog and return to its result.' :
    testProfile()?.rdma && !catalog.rdmaResource ? 'This test requires an RDMA device resource configured on the runner.' :
    !src || !dst ? 'No eligible node pair for this test case. Check node readiness and device capacity.' : '');
  $('traffic-test-message').textContent = reason;
  $('traffic-test-submit').disabled = Boolean(reason) || testSubmitting || !testCase();
}

function testResult(run) {
  const root = $('traffic-test-result');
  root.replaceChildren();
  if (!run) return;
  const profile=catalog.profiles.find(p=>p.id===(run.test||'iperf-tcp'));
  const scenario=catalog.cases.find(c=>c.id===(run.case||'POD_TO_POD_DIFF_NODE'));
  root.append(text('h3',run.finished ? 'Last test' : 'Current test'), text('strong',[profile?.name||run.test,scenario?.name||run.case].filter(Boolean).join(' · ')),
    text('p',run.source.node+' → '+run.destination.node+' · '+new Date(run.started).toLocaleString()));
  const traffic = run.traffic;
  if (traffic?.delivered) {
    const stats=[];
    if(traffic.bytes!=null)stats.push(count(traffic.bytes)+' bytes received');
    if(traffic.bps!=null)stats.push((traffic.bps/1e6).toFixed(2)+' Mbit/s');
    if(traffic.transactionsPerSecond!=null)stats.push(traffic.transactionsPerSecond.toFixed(2)+' transactions/s');
    if(traffic.lostPercent!=null)stats.push(traffic.lostPercent.toFixed(2)+'% loss');
    if(traffic.jitterMs!=null)stats.push(traffic.jitterMs.toFixed(3)+' ms jitter');
    root.append(text('strong','Test passed'),text('p',stats.join(' · ')));
    if(scenario?.service && traffic.targetIP)root.append(text('p','Service IP '+traffic.targetIP+' → server '+traffic.destinationIP));
  } else if (traffic) root.append(text('strong','Test failed'),text('p',traffic.error || 'No completed transfer.'));
  else root.append(text('p','Test in progress. Waiting for the runner and collector samples.'));
  if (run.drop) root.append(text('p','Matching policy drop · '+run.drop));
  for (const n of run.nodes) {
    const card = text('section','','record');
    card.append(text('strong',n.node));
    for(const [role,endpoint] of [['Client',run.source],['Server',run.destination]]){
      const ip=endpoint.ip || (role==='Client'?traffic?.sourceIP:traffic?.destinationIP);
      if(endpoint.node===n.node && ip)card.append(text('p', [role,endpoint.pod,ip].filter(Boolean).join(' · ')));
    }
    if (n.state === 'disabled') card.append(text('p','Hardware offload disabled'));
    else if (!profile?.protocol) card.append(text('p','OVS data-path correlation is unavailable for this test type.'));
    else if (!n.paths?.length) card.append(text('p',run.finished ? 'Offload inconclusive. No active path matched the test data stream.' : 'Awaiting matching datapath evidence.'));
    for (const p of n.paths || []) {
      const detail=text('details','');
      detail.append(text('summary',(offloadLabels[p.status] || p.status)+' · '+(p.tuple.sourceIP === run.source.ip ? 'client → server' : 'server → client')+(p.issue?' · persistent issue':'')),
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
async function openTrafficTest(src,dst,network) {
  clearTimeout(testTimer);testEnabled=false;testRunning=false;testSubmitting=false;catalog=null;
  for(const id of ['profile','case','source','destination']) $('traffic-test-'+id).replaceChildren();
  $('traffic-test-description').textContent='';
  testContext=network && network!=='default' ? 'This test supports the default network. The selected link uses '+network+'.' : '';
  $('traffic-test-result').replaceChildren();$('traffic-test-submit').disabled=true;
  $('traffic-test-message').textContent='Loading tests and nodes…';testDialog.showModal();
  const seq=++testSequence;
  try {
    const options=await api('traffic-test/options');
    if(seq!==testSequence)return;
    catalog=options;
    fillTestChoices('traffic-test-profile',catalog.profiles,'iperf-tcp');
    selectTestProfile(src && src===dst ? 'POD_TO_POD_SAME_NODE' : 'POD_TO_POD_DIFF_NODE',src,dst);
    await refreshTest(seq);
  }catch(e){if(seq===testSequence)$('traffic-test-message').textContent=e.message}
}
$('offload-run-test').onclick=()=>openTrafficTest($('offload-node').value,'',$('offload-network').value);
$('traffic-test-profile').onchange=()=>selectTestProfile($('traffic-test-case').value,$('traffic-test-source').value,$('traffic-test-destination').value);
$('traffic-test-case').onchange=()=>selectTestNodes($('traffic-test-source').value,$('traffic-test-destination').value);
$('traffic-test-source').onchange=()=>updateTestDestination($('traffic-test-destination').value);
$('traffic-test-destination').onchange=updateTestForm;
testDialog.addEventListener('close',()=>{clearTimeout(testTimer);testSequence++});
$('traffic-test-form').onsubmit=async e=>{
  e.preventDefault();if ($('traffic-test-submit').disabled)return;
  $('traffic-test-submit').disabled=true;
  testSubmitting=true;
  const seq=++testSequence;
  try {
    const status=await api('traffic-test',{test:testProfile().id,case:testCase().id,sourceNode:$('traffic-test-source').value,destinationNode:$('traffic-test-destination').value,network:'default'});
    if(seq!==testSequence)return;
    testSubmitting=false;testRunning=true;updateTestForm();testResult(status.run);refreshTest(seq);
  } catch(err) {
    if(seq===testSequence){testSubmitting=false;updateTestForm();$('traffic-test-message').textContent=err.message}
  }
};
