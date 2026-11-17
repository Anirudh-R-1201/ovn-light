// SPDX-License-Identifier: Apache-2.0
module.exports=async function(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(url); await page.waitForSelector('.finding');
 await page.locator('[data-page="routing"]').click();
 await page.waitForSelector('#routing-graph .infra-path');
 await page.locator('#routing-network').selectOption('cluster/blue');
 await page.waitForFunction(()=>document.querySelectorAll('#routing-graph .infra-path').length===1);
 if(!await page.locator('#routing-graph').textContent().then(s=>s.includes('203.0.113.1')&&!s.includes('192.0.2.1')&&s.includes('blue-uplink')))throw Error('Routing network filter or uplink association failed');
 await page.locator('#routing-graph .infra-node').last().click();
 if(!await page.locator('#routing-detail').textContent().then(s=>s.includes('PodNetwork')&&s.includes('Configured')&&s.includes('10.80.0.0/24')))throw Error('Peer detail lost advertisement evidence');
 await page.locator('#routing-uplinks button').click();
 if(!await page.locator('#routing-detail').textContent().then(s=>s.includes('br-blue')&&s.includes('GatewayReady')))throw Error('Uplink detail lost readiness evidence');
 await page.setViewportSize({width:390,height:844});
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Routing mobile overflow');
 await page.locator('[data-page="egressip"]').click();
 await page.getByRole('button',{name:'Inspect assigned paths →'}).click();
 await page.locator('#egressip-detail .infra-node').first().click();
 if(!await page.locator('#egressip-path-detail').textContent().then(s=>s.includes('OVN SNAT')&&s.includes('No exact external-traffic')))throw Error('Assignment mistaken for observed traffic');
 await page.evaluate(()=>loadRouting());
 if(!await page.locator('#egressip-path-detail').textContent().then(s=>s.includes('OVN SNAT')))throw Error('Refresh closed the selected EgressIP evidence');
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('EgressIP mobile overflow');
 const anp=await browser.newPage();anp.on('pageerror',e=>errors.push(e.message));
 await anp.route('**/api/state',async route=>{
  const response=await route.fetch(),state=await response.json();
  const f=state.findings[0];f.canRecommend=false;f.causes=[{type:'AdminNetworkPolicy',name:'guard',direction:'Ingress',rule:'0',action:'drop',acl:'demo-acl',admin:{kind:'AdminNetworkPolicy',name:'guard',priority:7,direction:'Ingress',ruleIndex:0,ruleName:'deny-private',explanation:'A NetworkPolicy allow cannot override an AdminNetworkPolicy Deny.',rule:{action:'Deny'},warnings:[]}}];
  await route.fulfill({response,json:{...state,findings:[f]}});
 });
 await anp.goto(url);await anp.locator('.finding button').click();
 if(!await anp.locator('.admin-evidence').textContent().then(s=>s.includes('Priority 7')&&s.includes('Rule 1')&&s.includes('deny-private')))throw Error('ANP evidence omitted rule attribution');
 if(await anp.getByRole('button',{name:'Choose the intended connection'}).count()||await anp.getByRole('button',{name:'Review a scoped allow rule'}).count())throw Error('ANP deny offered an ineffective NetworkPolicy fix');
 await page.close();await anp.close();
};
