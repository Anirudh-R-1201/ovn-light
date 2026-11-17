/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const offloadLabels={hardware:'Offload observed',partial:'Partial offload',software:'Software processing',failure:'Provider failure',unknown:'Unknown',pending:'Connection setup','not-expected':'Not evaluated'};
const offloadColor=s=>s==='hardware'?'green':s==='failure'?'red':['partial','software','pending'].includes(s)?'amber':'';
let offloadRequest=0,offloadSearchTimer;
function offloadTitle(p){return `${endpoint(p.source)} → ${endpoint(p.destination)}${p.protocol?' · '+p.protocol:''}${p.destination.port?'/'+p.destination.port:''}`}
function offloadTime(t){return t&&Date.parse(t)>0?new Date(t).toLocaleTimeString():'unavailable'}
function offloadRaw(label,raw){const d=text('details','');d.append(text('summary',label),text('pre',raw));return d}
async function loadOffload(){
 const request=++offloadRequest;
 fillSelect($('offload-node'),state.nodes.map(n=>({label:n.name,value:n.name})),'All nodes');
 fillSelect($('offload-network'),state.networks.map(n=>({label:n.name,value:n.id})),'All networks');
 const q=new URLSearchParams({node:$('offload-node').value,network:$('offload-network').value,status:$('offload-status').value,search:$('offload-search').value,limit:'50'});
 try{
  const r=await api('offload?'+q);if(request!==offloadRequest)return;
  $('updated').textContent='Collected '+offloadTime(r.collectedAt);
  const nodes=list(r.nodes),enabled=nodes.filter(n=>n.state==='enabled').length;
  $('offload-coverage').replaceChildren(text('strong',enabled?`${enabled} inspected ${enabled===1?"node has":"nodes have"} hardware offload configured.`:nodes.every(n=>n.state==='disabled')&&nodes.length?'Hardware offload is disabled on the inspected nodes.':'Hardware offload configuration is not yet confirmed.'));
  $('offload-coverage').append(text('p',`Issues require at least 3 consecutive activity intervals spanning ${r.graceSeconds||60} seconds. New connections, counter resets, and gaps restart that observation period. Diagnostics are cached for up to one minute.`,'note'));
  if(state.mode==='demo')$('offload-coverage').append(text('p','Synthetic demonstration evidence. This does not represent hardware validation.','note'));
  $('offload-nodes').replaceChildren();
  for(const n of nodes){
   const card=text('article','','network-card'),top=text('div','','record-top');top.append(text('strong',n.name),badge(n.state==='enabled'?'Configured':n.state==='disabled'?'Disabled':'Unconfirmed',n.state==='enabled'?'amber':''));
   card.append(top,text('p',`${n.provider||'Provider unknown'} · OVS ${n.version||'version unknown'}`),text('p',`Cached flow status: ${count(n.counts.hardware)} hardware · ${count(n.counts.partial)} partial · ${count(n.counts.software)} software · ${count(n.counts.unknown)} unknown`),text('p',`Flows: ${offloadTime(n.capturedAt)} · Diagnostics: ${offloadTime(n.diagnosticsAt)}`,'note'));
   for(const error of list(n.errors))card.append(text('p',error,'error'));
   if(n.config&&Object.keys(n.config).length)card.append(offloadRaw('Offload configuration',Object.entries(n.config).map(([k,v])=>k+'='+v).join('\n')));
   if(n.stats)card.append(offloadRaw('Provider offload counters',n.stats));if(n.pmdStats)card.append(offloadRaw('Software PMD counters',n.pmdStats));
   if($('offload-node').value!==n.name)card.append(button('Inspect node',()=>{$('offload-node').value=n.name;loadOffload()}));
   $('offload-nodes').append(card);
  }
  $('offload-count').textContent=`${r.total} matching paths · ${r.issues} issues${r.omitted?' · '+r.omitted+' omitted':''}`;
  const root=$('offload-paths');root.replaceChildren();
  if(!list(r.paths).length)root.append(text('div',enabled?'No observed paths match these filters. Missing flow evidence does not prove full offload.':'No offload paths to evaluate. Offload is disabled or its configuration is not yet confirmed.','empty'));
  for(const p of list(r.paths)){
   const card=text('article','','offload-path record'),top=text('div','','record-top');top.append(text('strong',offloadTitle(p)),badge(p.issue?'Persistent issue':offloadLabels[p.status]||p.status,p.issue?'red':offloadColor(p.status)));card.append(top,text('p',`${p.node} · ${networkName(p.network)}`,'muted'),text('p',p.summary),text('p',`${p.activityDelta===undefined?'Activity baseline pending':count(p.activityDelta)+' largest stage packet delta'} · ${p.partialDelta===undefined?'Partial delta unavailable':count(p.partialDelta)+' largest partial-offload delta'}`,'note'),button('Inspect offload path →',()=>showOffload(p.id)));root.append(card);
  }
 }catch(e){if(request===offloadRequest)$('offload-coverage').replaceChildren(text('p',e.message,'error'))}
}
async function showOffload(id){
 const root=$('offload-detail-body');root.replaceChildren(text('p','Loading offload evidence…','muted'));if(!$('offload-detail').open)$('offload-detail').showModal();
 try{
  const r=await api('offload?'+new URLSearchParams({id})),p=list(r.paths)[0];
  if(!p){root.replaceChildren(text('h2','This path is no longer in the current collection.'),text('p','Refresh the Hardware Offload page to inspect current evidence.'));return}
  root.replaceChildren(text('h2',offloadTitle(p)),badge(offloadLabels[p.status]||p.status,offloadColor(p.status)),text('p',p.summary),text('p',`${p.node} · ${networkName(p.network)} · observed ${offloadTime(p.observedAt)}`,'muted'));
  if(p.issue)root.append(text('p','Persistent activity since '+offloadTime(p.since),'error'));
  root.append(text('p',p.guidance,'callout'));
  for(const w of list(p.warnings))root.append(text('p',w,'note'));
  if(list(p.conntrack).length){root.append(text('h3','Conntrack offload by direction'));for(const ct of p.conntrack){const c=text('div','','record');c.append(text('strong',`Zone ${ct.zone} · ${ct.direction||'direction unresolved'}`),text('p',`Original: ${ct.original} · Reply: ${ct.reply}`),badge(offloadLabels[ct.status]||ct.status,offloadColor(ct.status)));if(ct.reason)c.append(text('p',ct.reason));c.append(text('p','CT observation: '+offloadTime(ct.capturedAt),'note'));if(ct.raw)c.append(offloadRaw('Matched conntrack entry',ct.raw));root.append(c)}}
  root.append(text('h3','Datapath stages'));
  const stages=text('div','','steps');for(const st of list(p.stages)){const s=text('article','','step'),top=text('div','','step-title');top.append(text('strong',`recirc ${st.recirc} · in_port ${st.inPort}`),badge(offloadLabels[st.status]||st.status,offloadColor(st.status)));s.append(top,text('p',`${st.provider||'Provider unspecified'} · ${count(st.packets)} packets · ${count(st.partialPackets)} partial-offload packets`),text('p',`Since previous comparable poll: ${st.packetDelta===undefined?'unknown':count(st.packetDelta)} packets · ${st.partialDelta===undefined?'unknown':count(st.partialDelta)} partial-offload packets`,'note'));if(st.reason)s.append(text('p',st.reason,'callout'));s.append(offloadRaw('Raw datapath evidence',st.raw));stages.append(s)}root.append(stages,text('p','Counters describe individual stages and may cover multiple connections. An offloaded stage does not prove end-to-end hardware forwarding.','note'),button('Download evidence',()=>download('ovn-light-offload-'+p.id+'.json',JSON.stringify(p,null,2),'application/json')));
 }catch(e){root.replaceChildren(text('p',e.message,'error'))}
}
function renderOffloadIssues(){
 const root=$('offload-issues'),network=$('network-filter').value,node=$('node-filter').value,search=$('search').value.toLowerCase();
 const issues=list(state.offloadIssues).filter(p=>(!network||p.network===network)&&(!node||p.node===node)&&(!search||JSON.stringify(p).toLowerCase().includes(search)));
 root.replaceChildren();root.classList.toggle('hidden',!issues.length);if(!issues.length)return;
 root.append(text('h2','Hardware offload issues'),text('p','Persistent software activity on paths with offload capability evidence.','note'));
 for(const p of issues){const row=text('article','','offload-issue record');row.append(badge('OFFLOAD','amber'),text('h3',p.summary),text('p',`${p.node} · ${networkName(p.network)} · ${endpoint(p.source)} → ${endpoint(p.destination)}`),button('Inspect offload path →',()=>showOffload(p.id)));root.append(row)}
 if(state.offloadIssueCount>100)root.append(button('Browse offload issues',()=>{$('offload-status').value='issues';page('offload')}));
}
for(const id of ['offload-node','offload-network','offload-status'])$(id).onchange=()=>loadOffload();
$('offload-search').oninput=()=>{clearTimeout(offloadSearchTimer);offloadSearchTimer=setTimeout(loadOffload,250)};
