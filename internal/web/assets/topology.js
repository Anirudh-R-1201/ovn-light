/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const topologyState={graph:null,edge:null,connection:null,paused:false,request:0,initialized:false,camera:{x:0,y:0,k:1},positions:new Map(),layoutKey:''};
const trafficStatus={both:'Both ends observed',local:'Local forwarding observed',drop:'Drop observed in this window','cached-drop':'Cached drop evidence',gap:'Receipt unobserved across repeated collections','source-only':'Source observed · receipt unobserved','receiver-only':'Receiver observed · source unobserved',partial:'Partial observation coverage',cached:'Cached evidence · no measured activity'};
const trafficColor=s=>['both','local'].includes(s)?'var(--green)':s==='drop'?'var(--red)':['gap','source-only'].includes(s)?'var(--accent)':'var(--muted)';
function trafficRate(n){if(n===undefined||n===null)return 'Rate unavailable';let v=n*8,u='b/s';for(const unit of ['kb/s','Mb/s','Gb/s']){if(v<1000)break;v/=1000;u=unit}return `${v.toFixed(v<10?2:1)} ${u}`;}
function topologyCount(n,label){return `${count(n)} ${label}${n===1?'':'s'}`;}
function syncTopologyControls(){
 fillSelect($('topology-network'),state.networks.map(n=>({label:`${n.name} · ${n.id}`,value:n.id})),'All networks');
 $('topology-node-list').replaceChildren(...state.nodes.map(n=>new Option(n.name,n.name)));
 $('topology-namespace-list').replaceChildren(...[...new Set(list(state.pods).map(p=>p.namespace).filter(Boolean))].sort().map(n=>new Option(n,n)));
 if(!topologyState.initialized&&state.nodes.length>100)$('topology-level').value='zones';
 if(!topologyState.initialized&&state.networks.length){$('topology-network').value=state.networks.some(n=>n.id==='default')?'default':state.networks[0].id;topologyState.initialized=true;}
}
function topologyQuery(edge){const q=new URLSearchParams();for(const k of ['network','node','level','window','limit','nodes','nodeSelector','namespace','workload','zone','paths'])q.set(k,$('topology-'+k).value);q.set('filter',$('topology-filter').value);q.set('sort',$('topology-filter').value==='drop'?'drops':'rate');if(edge)q.set('edge',edge);return q.toString();}
async function loadTopology(force=false){
 if(topologyState.paused&&!force)return;
 const request=++topologyState.request;
 try{
  const g=await api('topology?'+topologyQuery());if(request!==topologyState.request)return;
  topologyState.graph=g;$('updated').textContent='Collected '+new Date(g.collectedAt).toLocaleTimeString();$('topology-errors').replaceChildren();renderTopologyGraph();
  const partial=topologyPartialPaths(g);$('topology-count').textContent=`${topologyCount(g.edges.length,'observation link')}${partial.groups.length?' · '+topologyCount(partial.groups.length,'partial node path'):''} · ${g.hiddenEdges} links hidden · ${g.hiddenNodes||0} groups hidden${g.hiddenIssues?' · '+g.hiddenIssues+' issues hidden':''} · ${topologyCount(g.samples,'collection')}`;
  $('topology-location').textContent=([$('topology-zone').value,$('topology-namespace').value,$('topology-workload').value,$('topology-node').value].filter(Boolean).join(' / ')||'Cluster')+' / '+$('topology-level').selectedOptions[0].textContent;
  $('topology-back').classList.toggle('hidden',!['node','nodes','nodeSelector','namespace','workload','zone'].some(k=>$('topology-'+k).value)&&$('topology-level').value==='nodes');
  $('topology-coverage').replaceChildren(...list(g.warnings).map(w=>text('p',w)));
  if(topologyState.edge){if(g.edges.some(e=>e.id===topologyState.edge))await inspectTopologyEdge(topologyState.edge);else{topologyState.edge=null;$('topology-detail').replaceChildren(text('h2','The selected link is outside this view'),text('p','Choose another link or adjust the filters.','muted'));}}
 }catch(e){if(request===topologyState.request)$('topology-errors').replaceChildren(text('p',e.message,'error'));}
}
function topologySVG(name,attributes){const e=document.createElementNS('http://www.w3.org/2000/svg',name);for(const [k,v]of Object.entries(attributes))e.setAttribute(k,v);return e;}
function topologyFocus(n){
 if(n.group==='zones'){$('topology-zone').value=n.name;$('topology-level').value='nodes';}
 else if(n.group==='namespaces'){$('topology-namespace').value=n.name;$('topology-level').value='workloads';}
 else if(n.group==='workloads'){$('topology-workload').value=n.name;$('topology-level').value='pods';}
 else if(n.node){$('topology-node').value=n.node;$('topology-level').value='pods';}else return;
 clearTopologySelection();resetTopologyCamera();loadTopology(true);
}
// Group by network and node direction only. Sharing a path does not establish
// that a source-side counter belongs to a particular receiving pod.
function topologyPartialPaths(g){
 if($('topology-level').value!=='pods')return {groups:[],graph:g};
 const nodes=new Map(g.nodes.map(n=>[n.id,n])),groups=new Map(),remaining=[];
 for(const edge of g.edges){
  const source=nodes.get(edge.source),destination=nodes.get(edge.destination);
  if(!edge.network||!source?.node||!destination?.node||(source.endpoint?.uid&&destination.endpoint?.uid)){remaining.push(edge);continue;}
  const key=JSON.stringify([edge.network,source.node,destination.node]);
  if(!groups.has(key))groups.set(key,{network:edge.network,source:source.node,destination:destination.node,entries:[]});
  groups.get(key).entries.push({edge,source,destination});
 }
 if(!groups.size)return {groups:[],graph:g};
 const used=new Set(remaining.flatMap(e=>[e.source,e.destination]));
 return {groups:[...groups.values()],graph:{...g,edges:remaining,nodes:g.nodes.filter(n=>used.has(n.id))}};
}
function topologyObservation(entry,side){
 const {edge,source,destination}=entry,known=side==='source'?source:destination;
 const card=button('',()=>inspectTopologyEdge(edge.id),'secondary topology-observation');
 card.dataset.topologyEdge=edge.id;card.dataset.side=side;
 card.setAttribute('aria-pressed',String(topologyState.edge===edge.id));
 const drop=['drop','cached-drop'].includes(edge.status),label=drop?'Drop observation':side==='source'?'Source pod identified':side==='destination'?'Destination pod identified':'Node observation';
 card.setAttribute('aria-label',`${label}: ${side==='node'?source.node+' to '+destination.node:known.name}`);
 card.append(text('span',label,'caption traffic-'+edge.status));
 if(side==='node')card.append(text('strong','Pods not identified'),text('small',`${source.endpoint?.ip||'Source address unknown'} → ${destination.endpoint?.ip||'Destination address unknown'}`));
 else card.append(text('strong',known.name),text('small',known.endpoint?.ip||'Address not identified'));
 const measures=text('div','','topology-observation-measures');
 if(drop)measures.append(text('strong',edge.status==='drop'?count(edge.droppedPackets)+' drops':'Cached drop evidence','traffic-'+edge.status));
 for(const [label,rate]of [['Source',edge.sourceBytesPerSecond],['Receiver',edge.receiverBytesPerSecond],['Local',edge.localBytesPerSecond]])if(rate!==undefined)measures.append(text('span',`${label}: ${trafficRate(rate)}`));
 if(!measures.childNodes.length)measures.append(text('span','Rate unavailable'));
 card.append(measures);
 if(drop&&edge.dropNodes?.length)card.append(text('small','Drop observed on '+edge.dropNodes.join(', ')));
 card.append(text('small',side==='source'?'Destination pod not identified':side==='destination'?'Source pod not identified':'Only the node path is identified'));
 card.append(text('span','Inspect observation →','accent'));
 return card;
}
function renderTopologyPartialPaths(root,groups){
 for(const group of groups){
  const panel=text('section','','topology-partial-path');panel.dataset.network=group.network;
  panel.setAttribute('aria-label',`${group.source} to ${group.destination}: pod match unconfirmed`);
  const header=text('div','','topology-path-heading');header.append(text('span',`${networkName(group.network)} · ${group.network}`,'caption'),text('span',topologyCount(group.entries.length,'independent observation link'),'note'));panel.append(header);
  const layout=text('div','','topology-path-layout');
  const source=text('div','','topology-path-side'),destination=text('div','','topology-path-side');
  source.append(text('span','SOURCE NODE','caption'),text('h3',group.source));destination.append(text('span','DESTINATION NODE','caption'),text('h3',group.destination));
  const sourceEntries=group.entries.filter(e=>e.source.endpoint?.uid),destinationEntries=group.entries.filter(e=>e.destination.endpoint?.uid);
  for(const entry of sourceEntries)source.append(topologyObservation(entry,'source'));
  for(const entry of destinationEntries)destination.append(topologyObservation(entry,'destination'));
  if(!sourceEntries.length)source.append(text('p','Source pod not identified in these observations.','topology-unidentified'));
  if(!destinationEntries.length)destination.append(text('p','Destination pod not identified in these observations.','topology-unidentified'));
  const gap=text('div','','topology-path-gap');gap.append(text('strong','Pod match unconfirmed'),text('span','Counters remain separate'));
  layout.append(source,gap,destination);panel.append(layout);
  for(const entry of group.entries.filter(e=>!e.source.endpoint?.uid&&!e.destination.endpoint?.uid))panel.append(topologyObservation(entry,'node'));
  panel.append(text('p','Grouped by network and node direction. These observations may describe different connections; the missing pod identities have not been inferred.','note'));
  root.append(panel);
 }
}
function markTopologySelection(){
 for(const el of $('topology-graph').querySelectorAll('button[data-topology-edge]'))el.setAttribute('aria-pressed',String(el.dataset.topologyEdge===topologyState.edge));
}
function renderTopologyGraph(){
 const host=$('topology-graph');host.replaceChildren();host.style.height='auto';if(!topologyState.graph)return;
 const {groups,graph:g}=topologyPartialPaths(topologyState.graph);
 renderTopologyPartialPaths(host,groups);
 if(groups.length&&!g.nodes.length)return;
 const viewport=text('div','','topology-viewport'),root=text('div','','topology-canvas');viewport.tabIndex=0;viewport.setAttribute('aria-label','Topology canvas. Use zoom buttons or mouse wheel to zoom; drag background to pan.');host.append(viewport);viewport.append(root);
 if(!g.nodes.length){root.style.height='auto';root.append(text('div','No matching observed traffic. Generate traffic and allow two collection rounds to measure rates.','empty'));return;}
 const width=host.clientWidth;
 if(width<620){viewport.classList.add('topology-list');root.style.height='auto';const map=new Map(g.nodes.map(n=>[n.id,n]));
  for(const e of g.edges){const a=map.get(e.source),b=map.get(e.destination),card=text('article','','topology-mobile-link');card.append(button(`${a.name} → ${b.name}`,()=>inspectTopologyEdge(e.id)),text('p',trafficStatus[e.status],'traffic-'+e.status),text('small',`Observed: ${(e.status==='drop'?count(e.droppedPackets)+' drops':trafficRate(e.sourceBytesPerSecond??e.localBytesPerSecond??e.receiverBytesPerSecond))} · ${e.connections} traffic groups`));if(a.node&&a.node===b.node)card.append(text('small','Same node: '+a.node));if($('topology-level').value==='nodes')card.append(button('Explore pods →',()=>topologyFocus(a)));root.append(card)}
  if(!g.edges.length)for(const n of g.nodes)root.append(button(n.name,()=>topologyFocus(n)));
  return;
 }
 const ordered=[...g.nodes].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));
 let height=Math.max(220,Math.ceil(ordered.length/2)*160+20);
 const coords=new Map();
 if($('topology-level').value==='pods'){
  const groups=new Map();for(const n of ordered){const key=n.node||'External / unresolved';if(!groups.has(key))groups.set(key,[]);groups.get(key).push(n)}
  const entries=[...groups].sort((a,b)=>a[0].localeCompare(b[0]));let y=0;
  for(let i=0;i<entries.length;i+=2){const pair=entries.slice(i,i+2),rows=Math.max(...pair.map(([,ns])=>ns.length));pair.forEach(([name,ns],col)=>{const x=col?width-110:110,label=text('div',name,'topology-group-label');label.style.left=(x-85)+'px';label.style.top=(y+8)+'px';root.append(label);ns.forEach((n,j)=>coords.set(n.id,{x,y:y+90+j*120}));});y+=rows*120+70;}
  height=Math.max(220,y);
 }else ordered.forEach((n,i)=>coords.set(n.id,{x:i%2?width-110:110,y:80+Math.floor(i/2)*160}));
 const layoutKey=[$('topology-level').value,$('topology-network').value,$('topology-node').value,$('topology-nodes').value,$('topology-nodeSelector').value,$('topology-namespace').value,$('topology-workload').value,$('topology-zone').value,width].join('|');
 if(topologyState.layoutKey===layoutKey){let next=Math.max(0,...[...topologyState.positions.values()].map(p=>p.y))+160;for(const n of ordered){const old=topologyState.positions.get(n.id);if(old)coords.set(n.id,old);else{coords.set(n.id,{x:110,y:next});next+=160;}}height=Math.max(height,...[...coords.values()].map(p=>p.y+100));}
 else{topologyState.layoutKey=layoutKey;topologyState.positions=new Map();}
 for(const [id,p]of coords)topologyState.positions.set(id,p);if(topologyState.positions.size>500)topologyState.positions=new Map(coords);
 root.style.height=height+'px';root.style.width=width+'px';
 const svg=topologySVG('svg',{width,height,role:'img','aria-label':'Directed observed traffic links. Use the labeled link buttons to inspect evidence.'});svg.classList.add('topology-wires');root.append(svg);
 const links=[],obstacles=[];
 for(const e of g.edges){const a=coords.get(e.source),b=coords.get(e.destination),color=trafficColor(e.status);let d;
  const inward=a.x<width/2?1:-1,reciprocal=g.edges.some(other=>other.source===e.destination&&other.destination===e.source);
  if(e.source===e.destination){d=`M ${a.x+inward*85} ${a.y-25} C ${a.x+inward*220} ${a.y-110},${a.x+inward*220} ${a.y+110},${a.x+inward*85} ${a.y+25}`;}
  else if(a.x===b.x){
   const bend=a.x+inward*(Math.min(300,width*.30)+(reciprocal&&e.source<e.destination?65:0)),port=a.x+inward*85;
   d=`M ${port} ${a.y} C ${bend} ${a.y},${bend} ${b.y},${port} ${b.y}`;
  }else{
   const sign=b.x>a.x?1:-1,x1=a.x+sign*85,x2=b.x-sign*85,m=(x1+x2)/2;
   d=`M ${x1} ${a.y} C ${m} ${a.y},${m} ${b.y},${x2} ${b.y}`;
   if(reciprocal){const dx=x2-x1,dy=b.y-a.y,length=Math.hypot(dx,dy)||1,ox=dy/length*55,oy=-dx/length*55;d=`M ${x1} ${a.y} C ${x1+dx/3+ox} ${a.y+dy/3+oy},${x1+dx*2/3+ox} ${a.y+dy*2/3+oy},${x2} ${b.y}`;}
  }
  const line=topologySVG('path',{d,fill:'none',stroke:color,'stroke-width':Math.max(2,Math.min(7,2+Math.log10(1+(e.sourceBytesPerSecond||e.localBytesPerSecond||0)/1000)))});line.classList.add('topology-link');line.dataset.topologyEdge=e.id;if(!['both','local','drop'].includes(e.status))line.setAttribute('stroke-dasharray','6 6');svg.append(line);
  const hit=topologySVG('path',{d,fill:'none',stroke:'transparent','stroke-width':22});hit.classList.add('topology-hit');hit.onclick=()=>inspectTopologyEdge(e.id);svg.append(hit);hit.onpointerenter=()=>root.querySelector(`[data-topology-edge="${e.id}"].topology-edge`)?.classList.add('hovered');hit.onpointerleave=()=>root.querySelector(`[data-topology-edge="${e.id}"].topology-edge`)?.classList.remove('hovered');
  const length=line.getTotalLength(),end=line.getPointAtLength(Math.max(0,length-5)),previous=line.getPointAtLength(Math.max(0,length-17)),angle=Math.atan2(end.y-previous.y,end.x-previous.x);
  const arrow=topologySVG('polygon',{points:`${end.x},${end.y} ${end.x-10*Math.cos(angle-.5)},${end.y-10*Math.sin(angle-.5)} ${end.x-10*Math.cos(angle+.5)},${end.y-10*Math.sin(angle+.5)}`,fill:color});svg.append(arrow);
  if(e.status==='drop'){
   const sourceNode=g.nodes.find(n=>n.id===e.source).node,destinationNode=g.nodes.find(n=>n.id===e.destination).node;
   const fraction=e.dropNodes?.includes(destinationNode) ? 0.86 : e.dropNodes?.includes(sourceNode) ? 0.14 : 0.5,p=line.getPointAtLength(length*fraction);
   const marker=topologySVG('g',{'aria-label':'Observed drop'});marker.classList.add('topology-hit');marker.onclick=()=>inspectTopologyEdge(e.id);marker.append(topologySVG('circle',{cx:p.x,cy:p.y,r:12,fill:'var(--bg)',stroke:color}));const cross=topologySVG('text',{x:p.x,y:p.y+5,'text-anchor':'middle',fill:color,'font-size':18});cross.textContent='×';marker.append(cross);svg.append(marker);obstacles.push({left:p.x-15,right:p.x+15,top:p.y-15,bottom:p.y+15});
  }
  const label=button(`${e.status==='drop'?'× ':['gap','source-only'].includes(e.status)?'? ':''}${(e.status==='drop'?count(e.droppedPackets)+' drops':trafficRate(e.sourceBytesPerSecond??e.localBytesPerSecond??e.receiverBytesPerSecond))} · ${e.connections}`,()=>inspectTopologyEdge(e.id),'secondary topology-edge');label.title=`${trafficStatus[e.status]} · ${networkName(e.network)}`;label.setAttribute('aria-label',`${g.nodes.find(n=>n.id===e.source).name} to ${g.nodes.find(n=>n.id===e.destination).name}: ${trafficStatus[e.status]}`);label.dataset.topologyEdge=e.id;label.setAttribute('aria-pressed',String(topologyState.edge===e.id));const sourceNode=g.nodes.find(n=>n.id===e.source).node;if(sourceNode&&sourceNode===g.nodes.find(n=>n.id===e.destination).node)label.title+=' · Same node: '+sourceNode;root.append(label);links.push({line,label});
 }
 for(const n of ordered){const c=coords.get(n.id),b=button('',()=>n.endpoint?showTopologyPod(n):topologyFocus(n),'secondary topology-node');b.replaceChildren(text('strong',n.name),text('small',n.endpoint?`${n.endpoint.ip||'Address unresolved'}`:`${n.pods} pods · ${networkName(n.network)}`),text('small',n.endpoint?networkName(n.endpoint.network):n.group?'Explore group →':n.node?'Explore pods →':'Inspect attached links','accent'));b.style.left=c.x+'px';b.style.top=c.y+'px';root.append(b);obstacles.push({left:c.x-b.offsetWidth/2,right:c.x+b.offsetWidth/2,top:c.y-b.offsetHeight/2,bottom:c.y+b.offsetHeight/2});}
 placeTopologyLabels(links,obstacles,width,height);
 setupTopologyCamera(viewport,root);
}
// Position labels on the rendered curve. When labels compete for space, move
// along their own paths so they remain attached after a resize or filter change.
function placeTopologyLabels(links,obstacles,width,height){
 const overlap=(a,b)=>Math.max(0,Math.min(a.right,b.right)-Math.max(a.left,b.left))*Math.max(0,Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top));
 for(const {line,label}of links){
  const length=line.getTotalLength(),w=label.offsetWidth+8,h=label.offsetHeight+8;let best;
  for(const fraction of [.5,.42,.58,.34,.66,.26,.74,.18,.82]){
   const p=line.getPointAtLength(length*fraction),box={left:p.x-w/2,right:p.x+w/2,top:p.y-h/2,bottom:p.y+h/2};
   const outside=Math.max(0,-box.left)+Math.max(0,box.right-width)+Math.max(0,-box.top)+Math.max(0,box.bottom-height);
   const score=outside*10000+obstacles.reduce((sum,o)=>sum+overlap(box,o),0);
   if(!best||score<best.score)best={p,box,score};if(score===0)break;
  }
  label.style.left=best.p.x+'px';label.style.top=best.p.y+'px';obstacles.push(best.box);
 }
}
function showTopologyPod(n){topologyState.edge=null;markTopologySelection();const root=$('topology-detail');root.replaceChildren(text('h2',n.name),text('p',`${n.node||'External'} · ${networkName(n.endpoint.network)} · ${n.endpoint.role||'Role unresolved'}`,'muted'),text('p','Select an attached traffic link to inspect its observations.','note'),button('Trace from this pod →',()=>openTrace({source:n.endpoint})));}
async function inspectTopologyEdge(id){
 topologyState.edge=id;markTopologySelection();const q=topologyQuery(id);$('topology-detail').replaceChildren(text('p','Loading connection evidence…','muted'));
 try{const g=await api('topology?'+q);if(topologyState.edge!==id||q!==topologyQuery(id))return;const e=g.edges.find(e=>e.id===id);if(!e){$('topology-detail').replaceChildren(text('p','This link has expired from the selected window.','note'));return;}
  const root=$('topology-detail');root.replaceChildren();const members=list(e.members);
  root.append(text('h2',`${topologyCount(e.connections,'traffic group')} · ${networkName(e.network)}`),text('p',trafficStatus[e.status],'traffic-'+e.status));
  if(e.connections>members.length)root.append(text('p',`Showing ${members.length} groups. Filter by node and switch to pod detail to narrow this link.`,'note'));
  const picker=document.createElement('select');picker.id='topology-connection';picker.setAttribute('aria-label','Traffic group');for(const c of members)picker.append(new Option(`${topologyEndpoint(c.source,'Source')} → ${topologyEndpoint(c.destination,'Destination')} · ${topologyTransport(c)}`,c.id));if(members.some(c=>c.id===topologyState.connection))picker.value=topologyState.connection;root.append(picker);
  const body=text('div','','topology-connection-detail');body.id='topology-connection-detail';root.append(body);
  picker.onchange=()=>{topologyState.connection=picker.value;renderTopologyConnection(members.find(c=>c.id===picker.value));};picker.onchange();
 }catch(e){$('topology-detail').replaceChildren(text('p',e.message,'error'));}
}
function topologyEndpoint(e,side){return e.pod?endpoint(e):e.ip||side+' pod not identified';}
function topologyTransport(c){return c.protocol&&c.destination.port?`${c.protocol}/${c.destination.port}`:`${c.protocol||'Protocol not identified'} · ${c.destination.port||'Port not identified'}`;}
function renderTopologyConnection(c){
 const root=$('topology-connection-detail');root.replaceChildren();if(!c)return;
 const local=c.source.node&&c.source.node===c.destination.node;
 const title=text('div','','record-top');title.append(text('h3',`${topologyEndpoint(c.source,'Source')} → ${topologyEndpoint(c.destination,'Destination')}`),badge(trafficStatus[c.status],c.status==='drop'?'red':['both','local'].includes(c.status)?'green':'amber'));root.append(title);
 root.append(text('p',`${c.source.node||'Unresolved source node'} → ${c.destination.node||'External / unresolved node'} · Last observed ${new Date(c.lastSeen).toLocaleTimeString()}`,'note'));
 if(local)root.append(text('p',`Both endpoints are on ${c.source.node}. Traffic between pods on the same node can still be blocked by network policy.`,'note'));
 if(!c.source.uid||!c.destination.uid){
  const known=c.source.uid?'The source pod is identified. The destination pod is not identified by this observation.':c.destination.uid?'The destination pod is identified. The source pod is not identified by this observation.':'The pod identities are not established by this observation.';
  root.append(text('p',known+' Other observations on the same node path may describe different traffic.','callout'));
 }
 if(!c.destination.port)root.append(text('p','The destination port was not retained in this observation. In the connection review, choose a specific port or explicitly select all ports for the intended protocol.','note'));
 const stats=text('div','','topology-measures');for(const [label,value]of [[local?'Local observation':'Source observation',local?c.local:c.sent],['Receiver observation',c.received],['Observed drops',c.dropped]]){if(!value.observed)continue;const el=text('div','','stat');el.append(text('span',label,'caption'),text('strong',label==='Observed drops'?(value.bytesPerSecond===undefined?'Unavailable':count(value.packets)+' packets'):trafficRate(value.bytesPerSecond)),text('small',value.bytesPerSecond!==undefined?`${count(value.packets)} measured packets · ${count(value.bytes)} observed bytes`:value.observed?'No comparable counter interval':'No attributable counter observed'));if(value.offloaded)el.append(text('small',value.software?'Mixed software/offload byte accounting':'Offload byte accounting is provider dependent'));stats.append(el)}root.append(stats);
 if(c.shared||(c.partial&&c.source.uid&&c.destination.uid))root.append(text('p',c.shared?'Shared counter: per-connection rates cannot be assigned.':'Path reconstruction is incomplete or includes an unmodeled transformation.','callout'));
 root.append(text('p','Source and receiver counts are independent observations. Forwarding actions do not prove physical transmission or application receipt. Packet loss is not calculated.','note'));
 const history=text('div','','topology-history');root.append(history);renderTrafficHistory(history,list(c.history));
 if(c.findingIDs?.length)root.append(button('Inspect drop evidence & review →',async()=>{try{state=await api('state');const f=state.findings.find(f=>c.findingIDs.includes(f.id));if(f)showDetail(f);else toast('This historical drop has expired from the current snapshot. Collect fresh evidence before reviewing a change.');}catch(e){toast(e.message)}}));
 if(!c.findingIDs?.length&&(c.source.uid||c.destination.uid))root.append(button('Review intended connection →',async()=>{try{state=await api('state');openIntent({source:c.source,destination:c.destination,protocol:c.protocol});}catch(e){toast(e.message)}}));
 const evidence=text('details','');evidence.append(text('summary',`Observation points (${list(c.observations).length} shown)`));for(const o of list(c.observations)){const row=text('div','','record');row.append(text('strong',`${o.node} · ${o.location} · ${o.verdict}${o.counterScope==='branch-input'?' · counter before conditional output':''}`),text('p',`${o.packetDelta===undefined?'Delta unavailable':count(o.packetDelta)+' packets since previous collection'} · ${o.offloaded?'offloaded':'software / unspecified'}`),text('pre',`${o.counterID}\n${o.start&&Date.parse(o.start)>0?new Date(o.start).toISOString():'Baseline unavailable'} → ${new Date(o.end).toISOString()}\n${list(o.warnings).join('\n')}`));evidence.append(row)}root.append(evidence);
 if(c.source?.uid)root.append(button('Simulate this connection →',()=>openTrace(c)));
}
function renderTrafficHistory(root,points){
 const rates=points.flatMap(p=>[p.sourceBytesPerSecond,p.receiverBytesPerSecond]).filter(v=>v!==undefined);
 if(!rates.length){root.append(text('p','No comparable forwarding-rate history for this observation.','note'));return;}
 if(points.length<2){root.append(text('p','Rate history becomes available after additional collection rounds.','note'));return;}
 const width=Math.max(240,root.clientWidth),height=150,max=Math.max(1,...rates),start=Date.parse(points[0].at),end=Date.parse(points.at(-1).at);if(end<=start)return;
 const svg=topologySVG('svg',{width:'100%',height,viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'Observed source and receiver rates over collection intervals. Gaps indicate unavailable rates.'});
 for(const [key,color]of [['sourceBytesPerSecond','var(--accent)'],['receiverBytesPerSecond','var(--green)']]){let d='',active=false;for(const p of points){if(p[key]===undefined){active=false;continue}const x=15+(Date.parse(p.at)-start)/(end-start)*(width-30),y=110-p[key]/max*85;d+=`${active?'L':'M'} ${x} ${y} `;active=true;svg.append(topologySVG('circle',{cx:x,cy:y,r:3,fill:color}));}svg.append(topologySVG('path',{d,fill:'none',stroke:color,'stroke-width':2}));}
 for(const [label,x,y,anchor]of [[trafficRate(max),15,15,'start'],[new Date(start).toLocaleTimeString(),15,140,'start'],[new Date(end).toLocaleTimeString(),width-15,140,'end']]){const t=topologySVG('text',{x,y,'text-anchor':anchor,fill:'var(--muted)','font-size':11});t.textContent=label;svg.append(t)}root.append(svg,text('p','Source rate — amber · Receiver rate — green','note'));
}
function clearTopologySelection(){topologyState.edge=null;topologyState.connection=null;$('topology-detail').replaceChildren(text('h2','Select traffic to inspect'),text('p','Inspect protocols, observed rates and drop evidence.','muted'));}
for(const id of ['network','filter','window','level','node','limit','nodes','nodeSelector','namespace','workload','zone','paths'])$('topology-'+id).onchange=()=>{clearTopologySelection();resetTopologyCamera();loadTopology(true);};
$('topology-back').onclick=()=>{for(const id of ['node','nodes','nodeSelector','namespace','workload','zone'])$('topology-'+id).value='';$('topology-level').value=state.nodes.length>100?'zones':'nodes';clearTopologySelection();resetTopologyCamera();loadTopology(true);};
$('topology-pause').onclick=()=>{topologyState.paused=!topologyState.paused;$('topology-pause').textContent=topologyState.paused?'Resume updates':'Pause updates';if(!topologyState.paused)loadTopology(true);};
let topologyWidth=0;new ResizeObserver(()=>{const width=$('topology-graph').clientWidth;if(width>0&&Math.abs(width-topologyWidth)>2){topologyWidth=width;renderTopologyGraph();}}).observe($('topology-graph'));
