// SPDX-License-Identifier: Apache-2.0
module.exports=async(browser,url,errors)=>{
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(url);await page.locator('[data-page="offload"]').click();
 await page.waitForSelector('.offload-path');
 if(!await page.locator('#offload-coverage').textContent().then(t=>t.includes('Synthetic')))throw new Error('Offload demo lacks synthetic label');
 await page.locator('#offload-status').selectOption('failure');
 await page.waitForFunction(()=>document.querySelectorAll('.offload-path').length===1&&document.querySelector('.offload-path').textContent.includes('Provider failure'));
 await page.locator('.offload-path button').click();await page.waitForSelector('#offload-detail[open] .step');
 if(!await page.locator('#offload-detail-body').textContent().then(t=>t.includes('Zone 64000')&&t.includes('Original: hardware · Reply: hardware')&&t.includes('Synthetic example: action is unsupported')))throw new Error('Offload inspector lost CT/stage failure evidence');
 await page.locator('#offload-detail .close').click();
 await page.locator('#offload-status').selectOption('');await page.locator('#offload-network').selectOption('analytics/data');
 await page.waitForFunction(()=>document.querySelectorAll('.offload-path').length===1&&document.querySelector('.offload-path').textContent.includes('analytics/worker'));
 if(await page.locator('#offload-paths').textContent().then(t=>t.includes('storefront/web')))throw new Error('Offload network filter leaked');
 await page.locator('#offload-network').selectOption('');await page.locator('#offload-node').selectOption('kind-worker2');
 await page.waitForFunction(()=>document.querySelector('#offload-coverage').textContent.includes('disabled'));
 if(await page.locator('.offload-path').count())throw new Error('Disabled node generated offload warnings');
 await page.locator('#offload-node').selectOption('kind-worker');await page.locator('#offload-status').selectOption('partial');await page.waitForSelector('.offload-path');
 if(!await page.locator('.offload-path').textContent().then(t=>t.includes('60 largest partial-offload delta')))throw new Error('Partial packet delta missing');
 if(process.env.OVN_LIGHT_SCREENSHOTS)await page.screenshot({path:process.env.OVN_LIGHT_SCREENSHOTS+'/offload.png',fullPage:true});
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:width===390?844:1100});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('Offload mobile overflow');
  await page.locator('.offload-path button').click();await page.waitForSelector('#offload-detail[open] .step');
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('Offload detail overflow');
  if(await page.locator('#offload-detail').getByRole('button',{name:/apply|allow|restart/i}).count())throw new Error('Offload diagnosis offered an unreviewed mutation');
  await page.locator('#offload-detail .close').click();
 }
 // Exercise issue navigation independently of the live counter grace period.
 await page.route('**/api/state',async route=>{const response=await route.fetch(),state=await response.json();const report=await(await page.request.get(url+'/api/offload?status=failure')).json();const p=report.paths[0];await route.fulfill({response,json:{...state,offloadIssueCount:1,offloadIssues:[{id:p.id,node:p.node,network:p.network,source:p.source,destination:p.destination,summary:'Persistent provider-reported offload failure.'}]}})});
 await page.locator('[data-page="issues"]').click();await page.waitForSelector('.offload-issue');await page.locator('.offload-issue button').click();await page.waitForSelector('#offload-detail[open] .step');
 await page.close();
};
