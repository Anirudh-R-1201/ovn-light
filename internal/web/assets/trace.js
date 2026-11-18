/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
let traceContext=null, traceBusy=false;
const traceEndpointValue=e=>JSON.stringify(e);
async function loadTraceContext(){
 traceContext=await api('trace/context');state={...state,pods:traceContext.pods};
 const networks=[...new Set(list(traceContext.pods).map(p=>p.network))].filter(Boolean).sort();
 fillSelect($('trace-network'),networks.map(n=>({label:networkName(n)+' · '+n,value:n})));
 tracePodOptions();
 fillSelect($('trace-service'),list(traceContext.services).filter(s=>s.spec.clusterIP&&s.spec.clusterIP!=='None').map(s=>({label:`${s.metadata.namespace}/${s.metadata.name} · ${s.spec.clusterIP}`,value:JSON.stringify(s)})),'Choose Service…');
 traceDestinationKind();
}
function tracePodOptions(){
 const pods=list(traceContext?.pods).filter(p=>p.network===$('trace-network').value);
 const options=pods.map(p=>({label:`${endpoint(p)} · ${p.ip} · ${p.node||'Node unknown'}`,value:traceEndpointValue(p)}));
 fillSelect($('trace-source'),options,'Choose source…');fillSelect($('trace-destination'),options,'Choose destination…');
}
function traceDestinationKind(){
 const kind=$('trace-kind').value;
 for(const name of ['destination','service','ip']){const active=name==={pod:'destination',service:'service',ip:'ip'}[kind];$('trace-'+name+'-field').classList.toggle('hidden',!active);$('trace-'+name).required=active;}
 $('trace-backends-field').classList.toggle('hidden',kind!=='service');$('trace-service-note').classList.toggle('hidden',kind!=='service');
 $('trace-dns-name').disabled=kind==='service';
}
function traceServicePort(){if(!$('trace-service').value)return;const s=JSON.parse($('trace-service').value),p=list(s.spec.ports).find(p=>p.protocol===$('trace-protocol').value);if(p)$('trace-port').value=p.port;}
function traceRequest(){
 if(!$('trace-form').reportValidity())return null;
 const kind=$('trace-kind').value,r={source:JSON.parse($('trace-source').value),destination:{},protocol:$('trace-protocol').value,port:Number($('trace-port').value),sourcePort:Number($('trace-source-port').value),state:$('trace-state').value,ovs:$('trace-ovs').checked,allBackends:$('trace-backends').checked};
 if(kind==='pod')r.destination=JSON.parse($('trace-destination').value);
 else if(kind==='service'){const s=JSON.parse($('trace-service').value);r.service={namespace:s.metadata.namespace,name:s.metadata.name,uid:s.metadata.uid};}
 else r.destination={ip:$('trace-ip').value.trim(),network:r.source.network};
 return r;
}
async function traceOperation(run){
 if(traceBusy)return;traceBusy=true;$('trace-fields').disabled=true;$('trace-status').className='callout';$('trace-status').textContent='Running requested diagnostic…';$('trace-check').replaceChildren();
 try{await run();$('trace-status').textContent='';$('trace-status').className='';}catch(e){$('trace-status').className='error';$('trace-status').textContent=e.message;if(e.result?.service)renderTraceServiceFailure(e.result);}
 finally{traceBusy=false;$('trace-fields').disabled=false;traceDestinationKind();}
}
function renderTraceServiceFailure(r){const root=$('trace-result');root.replaceChildren(text('h2','Service backend check'));for(const w of list(r.service.warnings))root.append(text('p',w,'callout'));root.append(text('p',`${r.service.ref.namespace}/${r.service.ref.name} · ${list(r.service.backends).length} eligible ready pod backends`));}
function traceStatusLabel(s){return {'predicted-drop':'Predicted drop','predicted-delivery':'Predicted logical delivery',handoff:'Handoff · path incomplete',unknown:'Outcome unresolved'}[s]||s;}
function renderTraceReport(report){
 const root=$('trace-result');root.replaceChildren(text('h2',report.mode==='demo'?'Demo simulation':'Simulation result'));
 root.append(text('p',`${new Date(report.at).toLocaleString()} · ${endpoint(report.request.source)} · ${report.request.source.ip} · ${networkName(report.request.source.network)} · ${report.request.protocol}/${report.request.port} · ${report.request.state}`,'note'));
 for(const warning of list(report.warnings))root.append(text('p',warning,'note'));
 if(list(report.qos).length){const d=text('details','');d.append(text('summary',`${report.qos.length} QoS policies select the source attachment`),text('p','These are candidate policies. Inspect destination classifiers and the simulated QoS stages for the selected packet. Simulation does not exercise a live policer or verify DSCP on the wire.','note'));for(const p of report.qos)d.append(text('h3',`${p.kind} ${p.namespace}/${p.name}`),text('pre',JSON.stringify(p.spec,null,2)));root.append(d)}
 if(report.service){root.append(text('h3',`Service ${report.service.ref.namespace}/${report.service.ref.name}`),text('p',`VIPs: ${list(report.service.ips).join(', ')} · ${list(report.service.backends).length} eligible ready pod backends`));for(const w of list(report.service.warnings))root.append(text('p',w,'callout'));}
 for(const result of list(report.results)){
  const card=text('article','','trace-result-card');card.append(badge(traceStatusLabel(result.status),result.status==='predicted-drop'?'red':result.status==='predicted-delivery'?'green':'amber'),text('h3',`${endpoint(report.request.source)} → ${endpoint(result.destination)}`),text('p',`${result.destination.ip}:${result.destination.port||report.request.port} · ${result.destination.node||'External destination'}`,'note'));
  for(const w of list(result.warnings))card.append(text('p',w,'callout'));
  const causes=list(result.segments).flatMap(s=>list(s.causes)),unique=[...new Map(causes.map(c=>[c.acl,c])).values()];
  for(const c of unique){const reason=text('div','','callout');reason.append(text('strong',c.type==='NetpolNamespace'?`Namespace isolation · ${c.namespace}`:`${c.type||'ACL'} · ${[c.namespace,c.name].filter(Boolean).join('/')}`),text('p',`${c.direction||''}${c.rule!==undefined&&c.rule!==''?' · Rule '+(Number(c.rule)+1):''} · ${c.action}`));if(c.type==='NetpolNamespace')reason.append(text('p','The namespace default-deny ACL is matched. Review the selected pods’ NetworkPolicies to decide which allowance is missing.'));if(c.type==='AdminNetworkPolicy')reason.append(text('p','An AdminNetworkPolicy Deny takes precedence over NetworkPolicy. Review the administrative rule.'));const evidence=text('details','');evidence.append(text('summary','ACL evidence'),text('pre',`ACL ${c.acl}\n${c.match||''}`));reason.append(evidence);card.append(reason);}
  for(const segment of list(result.segments)){
   const part=text('section','','trace-segment');part.append(text('h3',segment.node),text('p',segment.summary));
   const groups=[];for(const stage of list(segment.stages)){const key=[stage.pipeline,stage.datapath,stage.inPort,stage.outPort].join('/');if(groups.at(-1)?.key!==key)groups.push({key,stage,stages:[]});groups.at(-1).stages.push(stage);}
   const path=text('ol','','trace-path');for(const group of groups){const st=group.stage,li=text('li','','trace-hop'),d=text('details','');d.append(text('summary',`${group.stages.length} logical stages`));for(const item of group.stages)d.append(text('strong',item.name),text('pre',`${item.match||''}\n${list(item.actions).join('\n')}${item.flow?'\nFlow '+item.flow:''}`));li.append(text('strong',`${st.pipeline} · ${st.datapath}`),text('p',`${st.inPort||'Input'}${st.outPort?' → '+st.outPort:''}`,'note'),d);path.append(li);}part.append(path);
   for(const w of list(segment.warnings))part.append(text('p',w,'callout'));
   const raw=text('details','');raw.append(text('summary','Full OVN trace'),text('pre',segment.raw||'Illustrative demo stages'));part.append(raw);
   if(segment.ovs){const d=text('details','');d.append(text('summary','Source-node OVS trace'),text('p','OpenFlow and datapath prediction only. This does not confirm device programming or physical delivery.','note'),text('pre',segment.ovs));part.append(d);}card.append(part);
  }
  if(result.status==='predicted-drop'&&result.destination.uid&&policyAttachment(report.request.source)&&!unique.some(c=>c.type==='AdminNetworkPolicy'))card.append(button('Review an allowance for this connection →',()=>openIntent({source:report.request.source,destination:{...result.destination,port:result.destination.port||report.request.port},protocol:report.request.protocol}),'primary'));
  else if(result.status==='predicted-drop'&&unique.some(c=>c.type==='EgressFirewall')&&!result.destination.uid)card.append(button('Review EgressFirewall exception →',()=>openEgress({source:report.request.source,destination:{...result.destination,port:report.request.port},protocol:report.request.protocol}),'primary'));
  root.append(card);
 }
}
function renderTraceCheck(result){const el=$('trace-check');el.replaceChildren(text('h3',result.summary));el.className=result.success?'status-message':'callout';if(result.output)el.append(text('pre',result.output));}
$('trace-form').onsubmit=e=>{e.preventDefault();const r=traceRequest();if(r)traceOperation(async()=>{const report=await api('trace',r);renderTraceReport(report);});};
$('trace-tcp').onclick=()=>{const r=traceRequest();if(r)traceOperation(async()=>renderTraceCheck(await api('trace/tcp',r)));};
$('trace-dns').onclick=()=>{if(!$('trace-source').value){$('trace-source').reportValidity();return;}const r={source:JSON.parse($('trace-source').value),name:$('trace-dns-name').value.trim()};if($('trace-kind').value==='service'&&$('trace-service').value){const s=JSON.parse($('trace-service').value);r.service={namespace:s.metadata.namespace,name:s.metadata.name,uid:s.metadata.uid};}traceOperation(async()=>renderTraceCheck(await api('trace/dns',r)));};
$('trace-network').onchange=tracePodOptions;$('trace-kind').onchange=traceDestinationKind;$('trace-service').onchange=traceServicePort;$('trace-protocol').onchange=()=>{if($('trace-kind').value==='service')traceServicePort();};
async function openTrace(f){
 if($('detail').open)$('detail').close();
 page('trace',false);
 try{await loadTraceContext();const network=f?.source?.network||f?.destination?.network;if(network)$('trace-network').value=network;tracePodOptions();$('trace-kind').value=f?.destination?.uid?'pod':f?.destination?.ip?'ip':'pod';traceDestinationKind();
 for(const [id,e] of [['source',f?.source],['destination',f?.destination]]){if(!e)continue;const option=[...$('trace-'+id).options].find(o=>o.value&&JSON.parse(o.value).uid===e.uid&&JSON.parse(o.value).ip===e.ip);if(option)$('trace-'+id).value=option.value;}
 $('trace-port').value=f?.destination?.port||'';$('trace-protocol').value=['TCP','UDP'].includes(f?.protocol)?f.protocol:'TCP';$('trace-ip').value=f?.destination?.ip||'';
 }catch(e){toast(e.message)}
}
