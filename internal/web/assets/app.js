/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const $=id=>document.getElementById(id), list=x=>x||[], text=(tag,value,cls)=>{const n=document.createElement(tag);n.textContent=value;if(cls)n.className=cls;return n;};
let state={findings:[],networks:[],nodes:[],pods:[]}, plans=[], currentPlan=null, currentPage='issues', busy=false;
const endpoint=e=>e.pod?`${e.namespace}/${e.pod}`:e.ip||'Unresolved endpoint';
const networkName=id=>state.networks.find(n=>n.id===id)?.name||id||'Unresolved network';
const count=n=>new Intl.NumberFormat().format(n||0);
function badge(value,style=''){return text('span',value,`badge ${style}`)}
function button(label,fn,style='secondary'){const b=text('button',label,`button ${style}`);b.type='button';b.onclick=fn;return b;}
function toast(message){$('toast').textContent=message;$('toast').classList.remove('hidden');setTimeout(()=>$('toast').classList.add('hidden'),6500)}
async function api(path,body){const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{'Authorization':'Bearer '+(sessionStorage.getItem('ovn-light-token')||''),'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});if(response.status===401){if(!$('login').open)$('login').showModal();throw new Error('Access token required');}const result=await response.json();if(!response.ok){const error=new Error(result.error||response.statusText);error.result=result.result;throw error;}return result;}
function fillSelect(el,options,empty){const old=el.value;el.replaceChildren();if(empty!==undefined)el.append(new Option(empty,''));for(const o of options)el.append(new Option(o.label,o.value));if([...el.options].some(o=>o.value===old))el.value=old;}
async function load(){if(busy)return;try{if(currentPage==='trace'&&state.mode)return;if(['topology','offload','routing','egressip','qos'].includes(currentPage)&&state.mode){state={...state,...await api('context')};if(currentPage==='topology'){syncTopologyControls();await loadTopology()}else if(currentPage==='offload')await loadOffload();else if(currentPage==='qos')await loadQoS();else await loadRouting();return;}state=await api('state');render();if(currentPage==='qos')await loadQoS();if(currentPage==='changes')await loadPlans();if(currentPage==='topology')await loadTopology();if(currentPage==='offload')await loadOffload();if(['routing','egressip'].includes(currentPage))await loadRouting();}catch(e){if(e.message!=='Access token required')toast(e.message);}}
function render(){
 $('mode').textContent=state.mode==='live'?(state.writesEnabled?'Live · changes enabled':'Live · read only'):state.mode==='demo'?'DEMO · simulated evidence':'Snapshot · read only';$('mode').className='badge '+(state.mode==='live'?'green':'amber');
 $('updated').textContent=state.collecting?'Collecting…':state.collectedAt&&Date.parse(state.collectedAt)>0?'Collected '+new Date(state.collectedAt).toLocaleTimeString():'Awaiting first collection';
 const groups=groupFindings(state.findings);
 $('issue-count').textContent=groups.length+(state.offloadIssueCount||0);
 fillSelect($('network-filter'),state.networks.map(n=>({label:n.name,value:n.id})),'All networks');fillSelect($('node-filter'),state.nodes.map(n=>({label:n.name,value:n.name})),'All nodes');
 const unique=new Set(state.findings.map(f=>f.counterID)).size,correlated=groups.filter(g=>list(g.finding.causes).length).length;
 $('stats').replaceChildren();for(const [n,label,hint] of [[unique,'Drop flow counters','Not a connection or packet total'],[correlated,'Drop issues with ACL evidence','Equivalent paths grouped by shared counter'],[state.networks.length,'Networks discovered','Default, user-defined and attachments'],[state.nodes.length,'Nodes inspected',state.nodes.some(n=>list(n.errors).length)?'Collection gaps need attention':'See collector coverage and capabilities']]){const s=text('div','', 'stat');s.append(text('span',count(n),'number'),text('span',label,'caption'),text('span',hint,'hint'));$('stats').append(s)}
 renderFindings();renderNetworks();renderHealth();if(typeof syncTopologyControls==='function')syncTopologyControls();if(typeof syncRoutingControls==='function')syncRoutingControls();
}
function renderFindings(){if(typeof renderOffloadIssues==='function')renderOffloadIssues();const search=$('search').value.toLowerCase(),network=$('network-filter').value,node=$('node-filter').value,active=$('active-only').checked;
 const findings=state.findings.filter(f=>(!network||f.source.network===network||f.destination.network===network)&&(!node||f.node===node)&&(!active||f.delta>0)&&(!search||JSON.stringify([f.title,f.causes,f.source,f.destination]).toLowerCase().includes(search)));
 const groups=groupFindings(findings),pathCount=groups.reduce((n,g)=>n+g.paths.length,0);
 $('result-count').textContent=`${count(groups.length)} ${groups.length===1?'issue':'issues'} · ${count(pathCount)} evidence ${pathCount===1?'path':'paths'}`;$('findings').replaceChildren();
 if(!findings.length){const e=text('div','','empty');e.append(text('h3',state.collecting?'Looking inside the datapath…':'No matching drop issues'),text('p','This does not prove there are no drops. Generate traffic, inspect collector coverage, or change the filters.'));$('findings').append(e);return}
 for(const group of groups.slice(0,300)){const f=group.finding,card=text('article','','finding'),body=text('div',''),title=text('div','','finding-title');title.append(badge('DROP','red'),text('strong',f.title));const meta=text('div','','finding-meta');meta.append(text('span',networkName(f.source.network)),text('span',f.node),text('span',list(f.causes).map(c=>`${c.type} ${c.namespace||c.name}`).join(' · ')||'ACL attribution unavailable'));body.append(title,meta);if(group.paths.length>1)body.append(text('p',`${count(group.paths.length)} evidence paths · one shared drop counter`,'finding-path-count note'));const actions=text('div','','finding-action');actions.append(text('small',`${f.delta===undefined?'Δ unavailable':'+'+count(f.delta)+' since last poll'} · ${count(f.packets)} cached packets${f.sharedCounter?' · shared':''}`),button(f.canRecommend?'Inspect & recommend →':'Inspect evidence →',()=>showDetail(f,group.paths)));card.append(body,actions);$('findings').append(card)}
 if(groups.length>300)$('findings').append(text('p','Showing the first 300 issues. Use filters to narrow the result.','note'));
}
function showDetail(f,paths=[f]){const body=$('detail-body');body.replaceChildren(text('h2',f.title));
 if(paths.length>1){
  const context=text('div','','callout');context.append(text('strong',`${count(paths.length)} evidence paths share one drop counter.`),text('p','These are compatible reconstructed paths, not separate confirmed connections. The shared packet count is shown once; selecting a path does not assign those packets to it.'));
  const label=text('label','Evidence path'),select=text('select','');select.id='detail-path';
  paths.forEach((p,i)=>select.append(new Option(`Path ${i+1} · ${p.steps.length} stages · ${p.id}`,String(i))));
  select.value=String(paths.indexOf(f));select.onchange=()=>{showDetail(paths[Number(select.value)],paths);$('detail-path').focus()};label.append(select);context.append(label);body.append(context);
 }
 body.append(badge(f.confidence==='connection'?'Connection identity recovered':'Partial identity','amber'));
 const path=text('div','','flow-path');for(const [idx,e] of [f.source,f.destination].entries()){if(idx)path.append(text('span','→','arrow'));const node=text('div','','endpoint');node.append(text('small',idx?'DESTINATION':'SOURCE'),text('strong',endpoint(e)),text('span',`${e.ip||(!idx&&f.sourceContext?.address)||'Wildcard address'} · ${networkName(e.network)}`));if(e.node)node.append(text('span','Node: '+e.node));path.append(node)}body.append(path);
 renderSourceContext(body,f);
 const causes=list(f.causes);body.append(text('h3','Policy attribution'));if(causes.length){for(const c of causes){body.append(text('p',`${c.type} · ${c.namespace||c.name||'unnamed'} · ${c.direction||'direction unknown'}`,'muted'));body.append(text('pre',`ACL ${c.acl}\n${c.action}: ${c.match}`));if(c.admin)renderAdminEvidence(body,c.admin);}if(causes.some(c=>c.type==='NetpolNamespace'))body.append(text('p','This is a namespace default-deny ACL. It identifies the isolation decision, not one uniquely responsible NetworkPolicy.','note'));}else body.append(text('p','The terminal datapath action drops packets, but the owning ACL could not be recovered.','muted'));
 if(list(f.warnings).length){const warnings=text('div','','callout');for(const w of f.warnings)warnings.append(text('div','• '+w));body.append(warnings)}
 const firewall=causes.some(c=>c.type==='EgressFirewall');
 if(!causes.some(c=>c.admin))body.append(button(firewall?'Review an EgressFirewall exception':f.canRecommend?'Review a scoped allow rule':'Choose the intended connection',()=>firewall?openEgress(f):openIntent(f),'primary'));body.append(text('h2','Reconstructed datapath path'));
 const steps=text('div','','steps');for(const s of f.steps){const step=text('div','','step'),title=text('div','','step-title');title.append(text('strong',`recirc ${s.recirc} · in_port ${s.inPort}`),badge(s.offloaded?'Hardware offloaded':'Software / unspecified',s.offloaded?'green':''),text('span',`${count(s.packets)} packets`,'muted'));step.append(title,text('pre',`${Object.entries(s.match).map(([k,v])=>`${k}=${v}`).join(', ')}\nactions: ${s.actions}\nUFID: ${s.id}`));if(s.openFlow){const d=text('details','');d.append(text('summary','OpenFlow translation evidence'),text('pre',s.openFlow));step.append(d)}steps.append(step)}body.append(steps,button('Simulate this connection →',()=>openTrace(f)));if(!$('detail').open)$('detail').showModal();}
function renderSourceContext(body,f){
 const context=f.sourceContext;if(!context)return;
 const section=text('section','','source-context');section.append(text('h3','Candidate senders'),text('p',`Source constraint: ${context.address||'Address not retained'} · ${f.source.node||'Node unidentified'}. Candidate network: ${networkName(context.network)}.`,'note'));
 section.append(text('p','These are inventory matches, not confirmed senders. Separate outgoing activity can help you choose the intended connection.','note'));
 for(const candidate of list(context.candidates)){
  const e=candidate.endpoint,card=text('div','','record'),heading=text('div','','record-top');heading.append(text('strong',endpoint(e)),badge('Unconfirmed','amber'));card.append(heading,text('p',`${e.ip} · ${networkName(e.network)} · ${e.node||'Node unidentified'}`),text('p',candidate.evidence));
  if(policyAttachment(e)&&f.destination.uid&&!list(f.causes).some(c=>c.admin))card.append(button('Review with this candidate →',()=>openIntent(f,e)));section.append(card);
 }
 if(context.totalCandidates>list(context.candidates).length)section.append(text('p',`Showing ${context.candidates.length} of ${context.totalCandidates} candidates. You can select another workload in the connection review.`,'note'));
 if(!list(context.candidates).length)section.append(text('p','No candidates could be identified from the available address, node and network constraints.','note'));
 body.append(section);
}
function renderNetworks(){const root=$('network-list');root.replaceChildren();for(const n of state.networks){const card=text('article','','network-card');card.append(text('div','◇','network-symbol'),text('h3',n.name),text('p',n.namespace||'Cluster scope'));const tags=text('div','','tags');tags.append(badge(n.role,'amber'),badge(n.topology||'Unknown topology'));card.append(tags,text('p',list(n.subnets).join(' · ')||'Subnet not advertised in network inventory'));const footer=text('footer','');footer.append(text('span',`${n.pods} workloads`),button('View topology',()=>{$('topology-network').value=n.id;page('topology')}),button('View drops',()=>{$('network-filter').value=n.id;page('issues');renderFindings()}));card.append(footer);root.append(card)}
 $('connections').replaceChildren();if(!list(state.connections).length)$('connections').append(text('div','No ClusterNetworkConnect resources discovered.','empty'));for(const c of list(state.connections)){const el=text('div','','record');el.append(text('h3',c.metadata.name),text('pre',JSON.stringify({spec:c.spec,status:c.status},null,2)));$('connections').append(el)}
}
function renderHealth(){$('global-errors').replaceChildren();for(const e of list(state.errors))$('global-errors').append(text('p',e,'error'));$('node-list').replaceChildren();for(const n of state.nodes){const el=text('div','','record'),top=text('div','','record-top');top.append(text('strong',n.name),badge(list(n.errors).length?'Coverage gaps':'Collection completed',list(n.errors).length?'amber':'green'));el.append(top,text('p',`${count(n.flows)} cached flows · ${count(n.offloaded)} marked offloaded · ${new Date(n.capturedAt).toLocaleString()}`));if(n.collection)el.append(text('p',`${(n.collection.durationMs/1000).toFixed(1)}s collection · ${count(n.collection.commands)} exec calls · ${(n.collection.bytes/1048576).toFixed(2)} MiB read · ${n.collection.metadataCached?'OVN metadata cache hit':'OVN metadata refreshed'} · ${count(n.collection.detraceHits)} translation cache hits`));if(list(n.errors).length){const d=text('details',''),ul=text('ul','');d.open=true;d.append(text('summary',`${n.errors.length} collection messages`));for(const error of n.errors)ul.append(text('li',error));d.append(ul);el.append(d)}$('node-list').append(el)}}
async function loadPlans(){plans=await api('plans');$('change-list').replaceChildren();if(!plans.length)$('change-list').append(text('div','No proposals yet. Start by reviewing a connection or inspecting a drop.','empty'));for(const p of plans){const row=text('div','','record'),top=text('div','','record-top');top.append(text('strong',p.summary),badge(p.status,p.status==='verified'?'green':'amber'));row.append(top,text('p',new Date(p.createdAt).toLocaleString()+' · '+p.id),text('p',p.verification||'Review pending'),button('Open proposal',()=>showPlan(p)));$('change-list').append(row)}}
function page(name,initialize=true){currentPage=name;document.querySelectorAll('.page').forEach(p=>p.classList.toggle('hidden',p.id!==name));document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.page===name));$('page-name').textContent={issues:'Issues',topology:'Topology',trace:'Trace',networks:'Networks',changes:'Changes',health:'Collectors',offload:'Hardware Offload',routing:'Routing',egressip:'EgressIP',qos:'QoS'}[name];if(name==='trace'){if(initialize)loadTraceContext().catch(e=>toast(e.message));}else if(name==='topology')loadTopology(true);else if(name!=='changes')load();if(name==='changes')loadPlans().catch(e=>toast(e.message))}
document.querySelectorAll('.nav').forEach(n=>n.onclick=()=>page(n.dataset.page));document.querySelectorAll('.close').forEach(b=>b.onclick=()=>b.closest('dialog').close());for(const id of ['search','network-filter','node-filter','active-only'])$(id).addEventListener(id==='search'?'input':'change',renderFindings);
let intentFinding=null;
const policyAttachment=p=>['NetworkPolicy','MultiNetworkPolicy'].includes(p.policyKind);
function intentScope(){
 const chosen=['source','destination'].map(id=>$(id).value?JSON.parse($(id).value):null).filter(Boolean);
 const candidates=chosen.length?chosen:state.pods.filter(p=>p.network===$('intent-network').value&&policyAttachment(p));
 const kinds=[...new Set(candidates.map(p=>p.policyKind))];
 const scope=$('intent-policy-scope');scope.replaceChildren();
 if(kinds.length!==1){scope.append(text('span','Choose attachments on the same primary or secondary network.'));return}
 const kind=kinds[0];scope.append(badge(kind,'amber'));
 if(kind==='NetworkPolicy')scope.append(text('p','A regular NetworkPolicy applies to the namespace’s primary network: the cluster default network (CDN), or its primary UDN.','note'));
 else{
  const nads=[...new Set(chosen.map(p=>p.nad).filter(Boolean))];
  scope.append(text('p','MultiNetworkPolicy targets this secondary network through its policy-for annotation.'+(nads.length?' NADs: '+nads.join(', '):''),'note'));
 }
}
function podOptions(){
 const pods=state.pods.filter(p=>p.network===$('intent-network').value&&policyAttachment(p));
 const options=pods.map(p=>({label:`${endpoint(p)} · ${p.ip}${p.nad?' · '+p.nad:''}`,value:JSON.stringify(p)}));
 fillSelect($('source'),options,'Choose source…');fillSelect($('destination'),options,'Choose destination…');intentScope();
}
function openIntent(f,candidate){
 if($('detail').open)$('detail').close();
 intentFinding=f||null;$('intent-form').reset();$('intent-form').querySelector('.form-error').textContent='';
 const observed=[...new Set([f?.source.network,f?.destination.network].filter(Boolean))];
 const networks=[...new Set([...state.pods.filter(policyAttachment).map(p=>p.network),...observed])];
 fillSelect($('intent-network'),networks.map(id=>({label:networkName(id)+' · '+id,value:id})),'Choose network…');
 $('intent-network').value=observed.length===1?observed[0]:'';
 $('intent-network').disabled=observed.length>0;
 $('intent-network-picker').classList.toggle('hidden',observed.length>0);
 const context=$('intent-network-context');context.classList.toggle('hidden',observed.length===0);
 context.replaceChildren(text('strong',observed.length===1?'Observed network: '+networkName(observed[0])+' · '+observed[0]:'This drop crosses networks. Review connectivity separately.'));
 if(f&&observed.length===0)$('intent-form').querySelector('.form-error').textContent='The drop did not identify a network. Choose it explicitly before reviewing a policy.';
 $('intent-form').querySelector('[type=submit]').disabled=observed.length>1;
 podOptions();
 if(f){
  for(const [id,e] of [['source',candidate||f.source],['destination',f.destination]]){
   const option=[...$(id).options].find(o=>{if(!o.value)return false;const p=JSON.parse(o.value);return p.uid===e.uid&&p.ip===e.ip&&(!e.nad||p.nad===e.nad)});
   if(option)$(id).value=option.value;
  }
  $('protocol').value=f.protocol||'TCP';$('port').value=f.destination.port||'';
 }
 const hint=$('intent-candidate-context');hint.classList.toggle('hidden',!f||!!f.source.uid);hint.textContent=candidate?`You selected ${endpoint(candidate)} as the intended sender. The drop does not confirm this pod as its source.`:'The sender is unconfirmed. Choose the workload whose traffic you intend to allow.';
 intentPortScope();intentScope();$('intent').showModal();
}
function intentPortScope(){const all=$('all-ports').checked,protocol=$('protocol').value;$('all-ports-label').textContent=`All ${protocol} ports`;$('port').disabled=all;$('port').required=!all;$('port').closest('label').classList.toggle('hidden',all);$('all-ports-note').classList.toggle('hidden',!all);$('all-ports-note').textContent=`Allow every ${protocol} destination port for the selected workload selectors, including future listeners.`;}
$('all-ports').onchange=intentPortScope;$('protocol').onchange=intentPortScope;
$('intent-network').onchange=podOptions;$('source').onchange=intentScope;$('destination').onchange=intentScope;$('new-intent').onclick=()=>openIntent();
$('intent-form').onsubmit=async e=>{e.preventDefault();const i={kind:'Policy',findingID:intentFinding?.id,source:JSON.parse($('source').value),destination:JSON.parse($('destination').value),protocol:$('protocol').value,port:$('all-ports').checked?0:Number($('port').value),allPorts:$('all-ports').checked};await prepare(i,'intent')};
let egressFinding=null;
function openEgress(f){
 for(const id of ['detail','intent'])if($(id).open)$(id).close();
 egressFinding=f||null;$('egress-form').reset();$('egress-form').querySelector('.form-error').textContent='';
 const pods=state.pods.filter(p=>p.network==='default'&&p.role==='primary');
 fillSelect($('egress-source'),pods.map(p=>({label:`${endpoint(p)} · ${p.ip}`,value:JSON.stringify(p)})),'Choose source…');
 $('egress-source').value='';$('egress-source').disabled=false;
 if(f?.source.uid){const option=[...$('egress-source').options].find(o=>o.value&&JSON.parse(o.value).uid===f.source.uid);if(option)$('egress-source').value=option.value;$('egress-source').disabled=!!option;}
 $('egress-ip').value=f?.destination.ip||'';$('egress-ip').readOnly=!!f?.destination.ip;
 $('egress-protocol').value=f?.protocol||'TCP';$('egress-protocol').disabled=!!f?.protocol;
 $('egress-port').value=f?.destination.port||'';$('egress-port').readOnly=!!f?.destination.port;
 const cause=list(f?.causes).find(c=>c.type==='EgressFirewall');
 $('egress-evidence').classList.toggle('hidden',!cause);$('egress-evidence').textContent=cause?`Observed EgressFirewall ${cause.namespace}/${cause.name||'unknown'}${cause.rule!==''?' · rule '+(Number(cause.rule)+1):''}. Review the exact connection before allowing it.`:'';
 $('egress-form').querySelector('[type=submit]').disabled=!!f?.source.network&&f.source.network!=='default';
 if(f?.source.network&&f.source.network!=='default')$('egress-form').querySelector('.form-error').textContent='This attachment is outside the supported primary default network.';
 $('egress').showModal();
}
$('external-intent').onclick=()=>openEgress();
$('egress-form').onsubmit=async e=>{e.preventDefault();if(!$('egress-source').value)return;await prepare({kind:'EgressFirewall',findingID:egressFinding?.id,source:JSON.parse($('egress-source').value),destination:{ip:$('egress-ip').value.trim(),network:'default'},protocol:$('egress-protocol').value,port:Number($('egress-port').value)},'egress');};
$('connect-networks').onclick=()=>{const options=state.networks.filter(n=>n.role.toLowerCase()==='primary'&&['UserDefinedNetwork','ClusterUserDefinedNetwork'].includes(n.kind)).map(n=>({label:n.id,value:n.id}));fillSelect($('network-a'),options,'Choose network…');fillSelect($('network-b'),options,'Choose network…');$('connect-form').querySelector('.form-error').textContent='';$('connect').showModal()};
$('connect-form').onsubmit=async e=>{e.preventDefault();await prepare({kind:'ClusterNetworkConnect',networks:[$('network-a').value,$('network-b').value],connectCIDR:$('connect-cidr').value.trim(),networkPrefix:Number($('network-prefix').value),services:$('connect-services').checked},'connect')};
async function prepare(intent,dialog){const b=$(dialog+'-form').querySelector('[type=submit]');b.disabled=true;$(dialog+'-form').querySelector('.form-error').textContent='';try{const plan=await api('plans',intent);$(dialog).close();showPlan(plan)}catch(e){$(dialog+'-form').querySelector('.form-error').textContent=e.message}finally{b.disabled=false}}
function actionStatus(message,status='pending'){const el=$('action-status');el.textContent=message;el.dataset.status=status;el.className=message?(status==='success'?'status-message':status==='error'?'error':'muted'):'hidden';}
function showPlan(p){currentPlan=p;const root=$('review-body');root.replaceChildren(text('h2',p.summary),badge(p.status,p.status==='verified'?'green':'amber'));root.append(text('p',`Proposal expires ${new Date(p.expiresAt).toLocaleTimeString()}. Changes run with the server’s Kubernetes credentials.`,'note'));
 if(p.scope){const scope=text('div','','callout');scope.id='review-scope';scope.append(badge(p.scope.policyKind,'amber'),text('p',`Affected network: ${networkName(p.scope.network)} · ${p.scope.network} (${p.scope.role})`));if(p.scope.policyKind==='MultiNetworkPolicy')scope.append(text('p','Target NADs: '+list(p.scope.nads).join(', ')));root.append(scope)}
 const verified=p.status==='verified'||p.verificationSucceeded&&['applied','verified'].includes(p.status);
 actionStatus(p.intent.allPorts&&verified?`TCP port ${p.verificationPort} verified successfully. `+p.verification:p.status==='verified'?'TCP connection verified successfully. '+p.verification:p.verification||'',verified||p.status==='rolled-back'?'success':p.verification?.startsWith('Not verified:')?'error':'pending');
 if(p.intent.allPorts)root.append(text('p',`Port scope: All ${p.intent.protocol} ports. The selected network and workload selectors still apply.`,'callout'));
 const warnings=text('div','','callout');for(const w of list(p.warnings))warnings.append(text('div','• '+w));root.append(warnings,text('h3','Affected scope'));const scope=text('ul','','scope-list');for(const a of list(p.affected))scope.append(text('li',a));root.append(scope,text('h3','Proposed manifest'),text('pre',p.manifests));
 if(p.qosChange){const before=text('details','');before.append(text('summary','Current QoS before this change'),text('pre',p.beforeManifest));root.append(before)}
 if(p.firewallChange){const c=p.firewallChange;root.append(text('p',`Insert one Allow rule before existing rule ${c.index+1} in ${c.namespace}/${c.name}. All other rules retain their order.`,'callout'));const before=text('details','');before.append(text('summary','Current EgressFirewall before this change'),text('pre',p.beforeManifest));root.append(before)}
 const review=text('label','','review-check'),check=document.createElement('input');check.type='checkbox';check.id='reviewed';review.append(check,text('span',p.qosChange?'I reviewed the QoS values and all affected attachments.':p.firewallChange?'I reviewed the ordered firewall change. This IP and port should be allowed for all pods in the source namespace.':p.intent.allPorts?`I reviewed the selectors and affected workloads. All ${p.intent.protocol} destination ports should be allowed.`:'I reviewed the selectors, destination port and affected workloads. This traffic should be allowed.'));root.append(review);
 const canApply=state.writesEnabled&&p.status==='review'&&new Date(p.expiresAt)>new Date();review.classList.toggle('hidden',!canApply);$('apply-plan').classList.toggle('hidden',!canApply);$('apply-plan').disabled=true;check.onchange=()=>$('apply-plan').disabled=!check.checked;
 const canVerify=state.writesEnabled&&['applied','verified'].includes(p.status)&&['NetworkPolicy','EgressFirewall'].includes(p.kind)&&p.intent.protocol==='TCP';$('verify-plan').classList.toggle('hidden',!canVerify);$('probe-port-field').classList.toggle('hidden',!canVerify||!p.intent.allPorts);$('probe-port').value=p.verificationPort||'';$('verify-plan').textContent=p.intent.allPorts?'Verify selected TCP port':'Verify TCP connection';$('rollback-plan').classList.toggle('hidden',!(state.writesEnabled&&list(p.applied).length));$('rollback-plan').textContent=p.qosChange?'Restore previous QoS':p.firewallChange?'Remove inserted allow rule':'Roll back created resources';if(!$('review').open)$('review').showModal();}
async function action(name){if(busy)return;const request={};if(name==='verify'&&currentPlan.intent.allPorts){request.port=Number($('probe-port').value);if(!Number.isInteger(request.port)||request.port<1||request.port>65535){actionStatus('Choose a listening TCP port (1–65535) to test. An all-ports allowance cannot be verified with a single probe.','error');$('probe-port').focus();return}}busy=true;document.querySelectorAll('#review button').forEach(b=>b.disabled=true);actionStatus(name==='verify'?'Verifying TCP connection from the source pod…':name==='apply'?'Applying reviewed change…':'Rolling back created resources…');try{const p=await api(`plans/${currentPlan.id}/${name}`,request);showPlan(p);}catch(e){if(e.result?.id)showPlan(e.result);actionStatus((name==='verify'?'TCP connection could not be verified. ':'')+e.message,'error');}finally{busy=false;document.querySelectorAll('#review button').forEach(b=>b.disabled=false);if($('reviewed'))$('apply-plan').disabled=!$('reviewed').checked;load()}}
$('apply-plan').onclick=()=>action('apply');$('verify-plan').onclick=()=>action('verify');$('rollback-plan').onclick=()=>{$('rollback-title').textContent=currentPlan.qosChange?'Restore the previous QoS spec?':currentPlan.firewallChange?'Remove the inserted allow rule?':'Remove this proposal’s resources?';$('rollback-description').textContent=currentPlan.qosChange?'The existing QoS resource is preserved. Rollback refuses to overwrite a spec changed by another writer.':currentPlan.firewallChange?'The existing EgressFirewall will be kept. Rollback removes only this proposal’s rule and refuses to modify a firewall whose spec has changed.':'Only the objects created by this proposal are removed. Objects changed since creation will be preserved and reported.';$('confirm').showModal()};$('confirm-rollback').onclick=()=>{$('confirm').close();action('rollback')};
function download(name,body,type){const url=URL.createObjectURL(new Blob([body],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('download-plan').onclick=()=>download(`ovn-light-${currentPlan.id}.yaml`,currentPlan.manifests,'application/yaml');$('export-snapshot').onclick=async()=>{try{download('ovn-light-snapshot.json',JSON.stringify(await api('snapshot'),null,2),'application/json')}catch(e){toast(e.message)}};
$('refresh').onclick=async()=>{if(busy)return;busy=true;$('refresh').disabled=true;$('updated').textContent='Collecting…';try{state=await api('refresh',{});render();if(currentPage==='topology')await loadTopology(true);if(currentPage==='offload')await loadOffload()}catch(e){toast(e.message)}finally{busy=false;$('refresh').disabled=false}};
$('login-form').onsubmit=async e=>{e.preventDefault();sessionStorage.setItem('ovn-light-token',$('token').value.trim());try{state=await api('state');$('login').close();$('token').value='';render()}catch(e){$('login-error').textContent=e.message}};
$('logout').onclick=()=>{sessionStorage.removeItem('ovn-light-token');$('login').showModal()};
load();setInterval(()=>{if(!$('login').open)load()},15000);
