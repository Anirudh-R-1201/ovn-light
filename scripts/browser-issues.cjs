// SPDX-License-Identifier: Apache-2.0
const assert=require('node:assert/strict');
module.exports=async function checkIssueGrouping(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 try{
  const state=await(await page.request.get(url+'/api/state')).json();
  const original=state.findings.find(f=>f.canRecommend);
  const paths=Array.from({length:20},(_,i)=>({...original,id:'evidence-'+i,sharedCounter:true,packets:355,delta:16,steps:[{...original.steps[0],id:'stage-'+i},original.steps.at(-1)]}));
  await page.route('**/api/state',route=>route.fulfill({json:{...state,findings:paths.flatMap(p=>[p,p]),offloadIssues:[],offloadIssueCount:2}}));
  await page.goto(url);
  await page.waitForSelector('.finding');
  assert.equal(await page.locator('.finding').count(),1);
  assert.equal(await page.locator('#issue-count').textContent(),'3');
  assert.equal(await page.locator('#result-count').textContent(),'1 issue · 20 evidence paths');
  assert.equal(await page.locator('.finding-action small').textContent(),'+16 since last poll · 355 cached packets · shared');
  assert.match(await page.locator('.finding-path-count').textContent(),/20 evidence paths/);
  assert.equal(await page.locator('#stats .stat').nth(1).locator('.number').textContent(),'1');
  await page.locator('#active-only').check();
  assert.equal(await page.locator('.finding').count(),1);
  await page.locator('#search').fill('no-such-workload');
  assert.equal(await page.locator('.finding').count(),0);
  await page.locator('#search').fill(original.source.pod);
  assert.equal(await page.locator('.finding').count(),1);
  await page.locator('#network-filter').selectOption(original.source.network);
  assert.equal(await page.locator('.finding').count(),1);

  // A shared counter can cover different workloads, ports and policy decisions.
  // Those must remain separate issues, including unresolved vs exact identities.
  const boundaries=await page.evaluate(f=>{
   const changes={
    node:{node:'another-node'},counter:{counterID:'another-counter'},
    network:{source:{...f.source,network:'blue'}},attachment:{source:{...f.source,nad:'team/blue'}},
    source:{source:{...f.source,uid:'another-pod'}},destination:{destination:{...f.destination,uid:'another-server'}},
    address:{destination:{...f.destination,ip:'192.0.2.2'}},port:{destination:{...f.destination,port:443}},
    unknownPort:{destination:{...f.destination,port:0}},protocol:{protocol:'UDP'},
    unresolved:{source:{network:f.source.network}},
    policy:{causes:f.causes.map(c=>({...c,acl:'another-acl'}))},
    direction:{causes:f.causes.map(c=>({...c,direction:'Egress'}))},
    confidence:{confidence:'partial'},recommendation:{canRecommend:false}
   };
   return Object.fromEntries(Object.entries(changes).map(([key,change])=>[key,groupFindings([f,{...f,...change}]).length]));
  },paths[0]);
  for(const [boundary,n] of Object.entries(boundaries))assert.equal(n,2,'Merged distinct '+boundary);
  assert.equal(await page.evaluate(f=>groupFindings([f,{...f,source:Object.fromEntries(Object.entries(f.source).reverse()),causes:f.causes.map(c=>Object.fromEntries(Object.entries(c).reverse()))}]).length,paths[0]),1);

  await page.locator('.finding button').click();
  assert.equal(await page.locator('#detail-path option').count(),20);
  assert.match(await page.locator('#detail-body .callout').first().textContent(),/not separate confirmed connections/);
  await page.locator('#detail-path').selectOption('19');
  assert.match(await page.locator('#detail-body .steps').textContent(),/stage-19/);
  assert.equal(await page.locator('#detail-path').inputValue(),'19');
  assert.ok(await page.locator('#detail').evaluate(el=>el.matches(':modal')));
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.locator('#detail-path').evaluate(el=>{const r=el.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth;}));
  let intent;
  await page.route('**/api/plans',route=>{
   intent=route.request().postDataJSON();
   return route.fulfill({status:400,json:{error:'Proposal request captured for grouping test'}});
  });
  await page.getByRole('button',{name:'Review a scoped allow rule',exact:true}).click();
  await page.getByRole('button',{name:'Generate proposal →',exact:true}).click();
  await page.getByText('Proposal request captured for grouping test',{exact:true}).waitFor();
  assert.equal(intent.findingID,'evidence-19');
  assert.equal(intent.port,original.destination.port);
  await page.locator('#intent .close').click();
  assert.ok(!await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth));
 }finally{await page.close()}
};
