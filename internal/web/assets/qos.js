/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const qosState={offset:0,selected:'',request:0};
async function loadQoS(){
 const request=++qosState.request;
 fillSelect($('qos-network'),state.networks.map(n=>({label:networkName(n.id),value:n.id})),'All networks');
 const query=new URLSearchParams({offset:qosState.offset,limit:25});for(const field of ['network','node','namespace','search'])query.set(field,$('qos-'+field).value);
 try{const r=await api('qos?'+query);if(request!==qosState.request)return;
  const coverage=$('qos-coverage');coverage.replaceChildren(text('p',`${r.stale?'STALE · ':''}${state.mode==='demo'?'DEMO · synthetic evidence · ':''}Collected ${new Date(r.at).toLocaleTimeString()}.`));for(const [key,value]of Object.entries(r.capabilities))coverage.append(badge(`${key}: ${value}`,value==='Available'?'green':'amber'));for(const w of r.warnings)coverage.append(text('p',w,'note'));
  const pages=$('qos-pages');pages.replaceChildren(text('span',`${r.total} policies · ${r.hidden} outside this page`));if(qosState.offset)pages.append(button('Previous',()=>{qosState.offset=Math.max(0,qosState.offset-25);loadQoS()}));if(qosState.offset+25<r.total)pages.append(button('Next',()=>{qosState.offset+=25;loadQoS()}));
  const root=$('qos-policies');root.replaceChildren();for(const p of r.policies){const card=text('article','','record');card.append(text('h3',`${p.kind} · ${p.namespace}/${p.name}`),text('p',`${p.networks.map(networkName).join(', ')||'Network selection unresolved'} · ${p.targetCount} selected source attachments · ${p.rules.length} rules`),text('p',p.kind==='NetworkQoS'?`Policy priority ${p.priority}`:'DSCP marking · first matching rule wins','note'),button('Inspect QoS →',()=>showQoS(p)));root.append(card)}if(!r.policies.length)root.append(text('p','No matching QoS policies discovered. API availability and collection errors are shown above.','empty'));
  const bw=$('qos-bandwidth');bw.replaceChildren();for(const b of r.bandwidth){const card=text('article','','record');card.append(text('strong',`${endpoint(b.endpoint)} · ${b.direction}`),text('p',`Requested ${b.requested} bit/s · ${b.programmedBitsPerSecond===undefined?'Programmed rate unavailable':b.programmedBitsPerSecond+' bit/s observed'}`),badge(b.state,b.state.includes('differ')?'amber':''));bw.append(card)}if(!r.bandwidth.length)bw.append(text('p','No default-network pod bandwidth annotations match these filters.','note'));
  if(qosState.selected){const p=r.policies.find(p=>p.uid===qosState.selected);if(p&&!$('qos-edit-form'))showQoS(p,false);else if(!p){qosState.selected='';$('qos-detail').replaceChildren(text('p','The selected policy is outside this view. Choose a current policy.','note'))}}
 }catch(e){$('qos-coverage').textContent='QoS refresh failed; any displayed data is last known. '+e.message}
}
function showQoS(p,focus=true){
 qosState.selected=p.uid;const root=$('qos-detail');root.replaceChildren(text('h2',`${p.kind} ${p.namespace}/${p.name}`));
 for(const w of p.warnings)root.append(text('p',w,'callout'));
 const status=text('details','');status.append(text('summary','Controller status and selectors'),text('pre',JSON.stringify({status:p.status,spec:p.spec},null,2)));root.append(status);
 for(const rule of p.rules){const row=text('article','','record');row.append(text('h3',`Rule ${rule.index+1} · DSCP ${rule.dscp}`),text('p',`${rule.rateKbps?rule.rateKbps+' kbps':'No bandwidth limit'}${rule.burstKbits?' · burst '+rule.burstKbits+' kilobits':''}`),text('pre',JSON.stringify({classifier:rule.classifier,podSelector:rule.podSelector},null,2)),button('Review value change →',()=>editQoS(p,rule)));root.append(row)}
 root.append(text('h3','Observed OVN programming'));
 for(const program of p.programs){const d=text('details','','record');d.append(text('summary',`${program.node} · ${program.network} · rule ${program.rule+1} · priority ${program.priority} · ${program.state}`),text('p',`Collected ${new Date(program.at).toLocaleString()} · Switches: ${program.switches.join(', ')||'None recovered'}`,'note'),text('pre',JSON.stringify({uuid:program.uuid,match:program.match,action:program.action,bandwidth:program.bandwidth},null,2)));root.append(d)}
 if(!p.programs.length)root.append(text('p','No owned OVN rows recovered. This does not by itself prove a programming failure.','note'));
 root.append(text('h3',`${p.targetCount} selected source attachments`),text('p','Showing up to 100 attachments and 100 programming records. Destination classifiers still determine which traffic matches.','note'));
 for(const e of p.targets){const row=text('div','','record');row.append(text('strong',`${endpoint(e)} · ${networkName(e.network)}`),text('p',`${e.node} · ${e.ip}`),button('View observed traffic →',()=>{$('topology-network').value=e.network;$('topology-node').value=e.node;$('topology-namespace').value=e.namespace;$('topology-workload').value=e.pod;$('topology-level').value='pods';resetTopologyCamera();page('topology')}),button('Simulate from this pod →',()=>openTrace({source:e})));root.append(row)}
 if(focus)root.scrollIntoView({block:'start'});
}
function editQoS(p,rule){
 const root=$('qos-detail');root.replaceChildren(text('h2',`Review rule ${rule.index+1} · ${p.namespace}/${p.name}`),text('p','This changes the existing rule’s values for every matching attachment. Network selectors, classifiers and rule order stay in the review manifest.','note'));
 const form=text('form','');form.id='qos-edit-form';form.className='qos-edit';const fields={};
 for(const [key,label,value,max]of [['dscp','DSCP',rule.dscp,63],...(p.kind==='NetworkQoS'?[['rateKbps','Rate (kbps; 0 removes limit)',rule.rateKbps||0,4294967295],['burstKbits','Burst (kilobits; 0 removes burst)',rule.burstKbits||0,4294967295]]:[])]){const l=text('label',label),input=document.createElement('input');input.type='number';input.name=key;input.min='0';input.max=String(max);input.step='1';input.required=true;input.value=value;l.append(input);fields[key]=input;form.append(l)}
 const error=text('p','','error'),submit=button('Generate reviewed proposal',()=>{},'primary');submit.type='submit';form.append(error,submit,button('Cancel',()=>showQoS(p)));
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{const request={kind:p.kind,namespace:p.namespace,name:p.name,uid:p.uid,rule:rule.index};for(const [key,input]of Object.entries(fields))request[key]=Number(input.value);showPlan(await api('qos/plans',request));}catch(e){error.textContent=e.message}finally{submit.disabled=false}};root.append(form);
}
for(const field of ['network','node','namespace','search'])$('qos-'+field).onchange=()=>{qosState.offset=0;qosState.selected='';$('qos-detail').replaceChildren(text('h2','Select a QoS policy'));loadQoS()};
