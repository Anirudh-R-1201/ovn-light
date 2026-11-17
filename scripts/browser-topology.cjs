// SPDX-License-Identifier: Apache-2.0
module.exports=async function checkPartialTopology(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 try{
  const state=await(await page.request.get(url+'/api/state')).json();
  const source=state.pods.find(p=>p.pod==='web-7b49'),destination=state.pods.find(p=>p.pod==='catalog-9dd4');
  const unknownSource={node:source.node,network:'default'},unknownDestination={node:destination.node,network:'default'};
  const makeNode=(id,endpoint)=>({id,name:endpoint.pod?endpoint.namespace+'/'+endpoint.pod:'Unresolved on '+endpoint.node,node:endpoint.node,network:endpoint.network,endpoint});
  const empty={observed:false,packets:0,bytes:0};
  const drop={id:'drop-group',network:'default',source:unknownSource,destination,protocol:'',status:'drop',partial:true,shared:false,sent:empty,received:empty,local:empty,dropped:{observed:true,packets:110,bytes:8140,bytesPerSecond:67.8},lastSeen:state.collectedAt,history:[{at:'2026-11-17T17:00:00Z'},{at:'2026-11-17T17:00:30Z'}],observations:[],findingIDs:[state.findings[0].id]};
  const nodes=[makeNode('source',source),makeNode('destination',destination),makeNode('unknown-source',unknownSource),makeNode('unknown-destination',unknownDestination)];
  const sent={id:'source-edge',source:'source',destination:'unknown-destination',network:'default',status:'partial',connections:1,sourceBytesPerSecond:10,droppedPackets:0,partial:true};
  const denied={id:'drop-edge',source:'unknown-source',destination:'destination',network:'default',status:'drop',connections:1,droppedPackets:110,partial:true,dropNodes:[destination.node],members:[drop]};
  let expanded=false;
  await page.route('**/api/state',route=>route.fulfill({json:{...state,findings:[{...state.findings[0],source:unknownSource,destination,canRecommend:false}]}}));
  await page.route('**/api/topology?*',route=>{
   const q=new URL(route.request().url()).searchParams;
   const allNodes=[...nodes],allEdges=[sent,denied];
   if(expanded){
    allNodes.push(makeNode('source-2',{...source,uid:'another-client',pod:'another-client'}));
    allEdges.push({...sent,id:'source-2-edge',source:'source-2',sourceBytesPerSecond:20});
    allEdges.push({...sent,id:'reverse-edge',source:'destination',destination:'unknown-source'});
    for(const n of nodes)allNodes.push({...n,id:'blue-'+n.id,network:'analytics/data',endpoint:{...n.endpoint,network:'analytics/data'}});
    allEdges.push({...sent,id:'blue-edge',source:'blue-source',destination:'blue-unknown-destination',network:'analytics/data'});
    allNodes.push(makeNode('unscoped-source',{...source,network:''}),makeNode('unscoped-destination',{...unknownDestination,network:''}));
    allEdges.push({...sent,id:'unscoped-edge',source:'unscoped-source',destination:'unscoped-destination',network:''});
   }
   const edges=allEdges.filter(e=>(!q.get('network')||e.network===q.get('network'))&&(!q.get('edge')||e.id===q.get('edge')));
   const used=new Set(edges.flatMap(e=>[e.source,e.destination]));
   return route.fulfill({json:{collectedAt:state.collectedAt,windowSeconds:120,nodes:allNodes.filter(n=>used.has(n.id)),edges,totalEdges:edges.length,hiddenEdges:0,truncated:false,warnings:[],retainedConnections:edges.length,samples:2}});
  });
  await page.goto(url);
  await page.locator('[data-page="topology"]').click();
  await page.locator('#topology-level').selectOption('pods');
  await page.waitForSelector('.topology-partial-path');
  if(await page.locator('.topology-partial-path').count()!==1)throw new Error('Partial observations were not grouped by node path');
  if(await page.locator('#topology-graph .topology-node').count())throw new Error('Unidentified endpoints became fake pod nodes');
  const panel=page.locator('.topology-partial-path');
  const panelText=await panel.textContent();
  if(!panelText.includes('Pod match unconfirmed')||!panelText.includes('80.0 b/s')||!panelText.includes('110 drops')||!panelText.includes('Drop observed on '+destination.node))throw new Error('Partial path lost independent rate/drop evidence');
  await page.getByRole('button',{name:'Drop observation: payments/catalog-9dd4',exact:true}).click();
  await page.waitForSelector('#topology-connection-detail .topology-measures');
  const detail=await page.locator('#topology-connection-detail').textContent();
  if(!detail.includes('Source pod not identified')||detail.includes('web-7b49'))throw new Error('Unknown source was filled from a neighboring observation');
  if(await page.locator('.topology-history svg').count())throw new Error('Missing rate history produced a misleading empty chart');
  if(await page.locator('#topology-connection-detail .topology-measures .stat').count()!==1)throw new Error('Unobserved measurement cards were shown as data');
  if(process.env.OVN_LIGHT_SCREENSHOTS)await page.screenshot({path:process.env.OVN_LIGHT_SCREENSHOTS+'/partial-topology.png',fullPage:true});
  await page.getByRole('button',{name:'Inspect drop evidence & review →',exact:true}).click();
  await page.getByRole('button',{name:'Choose the intended connection',exact:true}).click();
  if(await page.locator('#source').inputValue()!=='')throw new Error('A partial-path grouping selected a policy source');
  await page.locator('#intent .close').click();
  expanded=true;
  await page.locator('#topology-network').selectOption('');
  await page.waitForFunction(()=>document.querySelectorAll('.topology-partial-path').length===3);
  const forward=page.locator('.topology-partial-path[aria-label="kind-worker to kind-worker2: pod match unconfirmed"][data-network="default"]');
  if(await forward.locator('[data-side="source"]').count()!==2||await forward.locator('[data-side="destination"]').count()!==1)throw new Error('Multiple possible sources were collapsed into one pod pair');
  if(await forward.textContent().then(s=>s.includes('240')))throw new Error('Independent source counters were combined');
  if(await page.locator('.topology-partial-path[data-network=""]').count())throw new Error('Observations with unknown networks were grouped');
  if(await page.locator('.topology-partial-path[data-network="analytics/data"]').count()!==1)throw new Error('Overlapping networks were grouped together');
  await page.locator('#topology-network').selectOption('analytics/data');
  await page.waitForFunction(()=>document.querySelectorAll('.topology-partial-path').length===1);
  if(await page.locator('.topology-partial-path[data-network="default"]').count())throw new Error('Network filter retained a different path');
  await page.setViewportSize({width:390,height:844});
  await page.waitForFunction(()=>getComputedStyle(document.querySelector('.topology-path-layout')).gridTemplateColumns.split(' ').length===1);
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('Partial topology overflows on mobile');
  if(process.env.OVN_LIGHT_SCREENSHOTS)await page.screenshot({path:process.env.OVN_LIGHT_SCREENSHOTS+'/partial-topology-mobile.png',fullPage:true});
 }finally{await page.close();}
};
