// SPDX-License-Identifier: Apache-2.0
const assert=require('node:assert/strict');
module.exports=async function checkTrace(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 page.on('pageerror',e=>errors.push(e.message));
 try{
  await page.goto(url);await page.waitForSelector('.finding');
  const finding=await page.evaluate(()=>state.findings.find(f=>f.canRecommend));
  await page.evaluate(f=>openTrace(f),finding);
  assert.equal(await page.locator('#trace-state').inputValue(),'new');
  assert.equal(await page.locator('#trace-backends-field').isVisible(),false);
  await page.locator('#trace-run').click();
  await page.waitForSelector('.trace-result-card');
  assert.match(await page.locator('#trace-result').textContent(),/DEMO: illustrative output/);
  assert.match(await page.locator('#trace-result').textContent(),/Predicted drop/);
  assert.ok(await page.locator('.trace-hop').count()>0);
  await page.getByRole('button',{name:'Review an allowance for this connection →'}).click();
  assert.equal(JSON.parse(await page.locator('#source').inputValue()).uid,finding.source.uid);
  assert.equal(await page.locator('#port').inputValue(),String(finding.destination.port));
  await page.locator('#intent .close').click();
  let request;
  await page.route('**/api/trace/tcp',async route=>{request=route.request().postDataJSON();await route.fulfill({json:{success:false,summary:'TCP connection failed: timed out'}});});
  await page.locator('#trace-tcp').click();await page.waitForFunction(()=>document.getElementById('trace-check').textContent.includes('timed out'));
  assert.equal(request.source.uid,finding.source.uid);assert.equal(request.state,'new');
  assert.equal(await page.locator('#trace-run').isEnabled(),true);
  await page.route('**/api/trace/dns',route=>route.fulfill({json:{success:true,summary:'DNS lookup succeeded from the selected source pod.',output:'10.244.0.12'}}));
  await page.locator('#trace-dns-name').fill('api.payments.svc.cluster.local');await page.locator('#trace-dns').click();
  await page.waitForFunction(()=>document.getElementById('trace-check').textContent.includes('DNS lookup succeeded'));
  for(const width of [1440,390]){await page.setViewportSize({width,height:1100});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Trace page overflows viewport');}
  await page.setViewportSize({width:1440,height:1100});await page.screenshot({path:'/tmp/ovn-light-trace-ui.png',fullPage:true});
 }finally{await page.close();}
};
