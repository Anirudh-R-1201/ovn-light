// SPDX-License-Identifier: Apache-2.0
// Start `ovn-light --demo` before running. Playwright is an optional dev tool.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH||undefined,args:process.env.NO_SANDBOX?['--no-sandbox']:[]});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const url=process.env.OVN_LIGHT_URL||'http://127.0.0.1:8080';
  await page.goto(url);
  await page.waitForSelector('.finding');
  await page.getByRole('button',{name:'Inspect & recommend →'}).click();
  await page.getByRole('button',{name:'Review a scoped allow rule'}).click();
  if(await page.locator('#intent-network-picker').isVisible()||!await page.locator('#intent-network').isDisabled())throw new Error('Observed network can be changed');
  if(!await page.locator('#intent-policy-scope').textContent().then(s=>s.includes('NetworkPolicy')))throw new Error('Policy type was not inferred');
  await page.getByRole('button',{name:'Generate proposal →'}).click();
  await page.waitForSelector('#review[open]');
  if(!await page.locator('#review-scope').textContent().then(s=>s.includes('default (primary)')))throw new Error('Review omitted affected network');
  if(!await page.locator('#review-body pre').textContent().then(s=>s.includes('namespaceSelector')))throw new Error('Missing scoped proposal');
  if(await page.locator('#apply-plan').isVisible())throw new Error('Demo offered live apply');
  const proposal=(await (await page.request.get(url+'/api/plans')).json()).find(p=>p.kind==='NetworkPolicy'&&p.intent.port===8080);
  await page.locator('#review .close').click();
  await page.locator('.finding').filter({hasText:'analytics/worker'}).getByRole('button').click();
  await page.getByRole('button',{name:'Choose the intended connection'}).click();
  if(await page.locator('#intent-network').inputValue()!=='analytics/data')throw new Error('UDN proposal switched to CDN');
  await page.locator('#port').fill('5432');
  await page.getByRole('button',{name:'Generate proposal →'}).click();
  await page.waitForSelector('#review[open]');
  if(!await page.locator('#review-scope').textContent().then(s=>s.includes('NetworkPolicy')&&s.includes('analytics/data (primary)')))throw new Error('Primary UDN scope lost');
  await page.locator('#review .close').click();
  await page.locator('#new-intent').click();
  if(!await page.locator('#intent-network-picker').isVisible()||await page.locator('#intent-network').inputValue()!=='')throw new Error('Manual connection guessed a network');
  await page.locator('#intent .close').click();
  await page.setViewportSize({width:390,height:844});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('Mobile horizontal overflow');
  // Simulate probe responses to exercise both outcomes without enabling demo writes.
  const reviewPage=await browser.newPage({viewport:{width:1440,height:1000}});
  reviewPage.on('pageerror',e=>errors.push(e.message));
  let plan={...proposal,status:'applied',verification:'Applied; connectivity has not been verified.'},started,finish;
  await reviewPage.route('**/api/state',async route=>{
   const response=await route.fetch(),state=await response.json();
   await route.fulfill({response,json:{...state,mode:'live',writesEnabled:true}});
  });
  await reviewPage.route('**/api/plans',route=>route.fulfill({json:[plan]}));
  await reviewPage.route('**/api/plans/*/verify',async route=>{
   const response=await new Promise(resolve=>{finish=resolve;started();});
   await route.fulfill(response);
  });
  await reviewPage.goto(url);
  await reviewPage.locator('[data-page="changes"]').click();
  await reviewPage.getByRole('button',{name:'Open proposal'}).click();
  for(const width of [1440,390]){
   await reviewPage.setViewportSize({width,height:width===390?844:1000});
   for(const success of [true,false]){
    await reviewPage.locator('#review-body').evaluate(el=>{el.scrollTop=el.scrollHeight;});
    const requestStarted=new Promise(resolve=>{started=resolve;});
    await reviewPage.locator('#verify-plan').click();
    await requestStarted;
    if(!await reviewPage.locator('#verify-plan').isDisabled())throw new Error('Probe button remained enabled');
    if(!await reviewPage.locator('#action-status').textContent().then(s=>s.includes('Verifying TCP connection')))throw new Error('Missing foreground progress');
    plan={...plan,status:success?'verified':'applied',verification:success?'TCP connection established from the selected source pod to 10.0.0.2:8080. This verifies transport reachability, not application behavior.':'Not verified: connection timed out'};
    finish(success?{json:plan}:{status:400,json:{error:'connection timed out',result:plan}});
    await reviewPage.waitForFunction(status=>document.getElementById('action-status').dataset.status===status,success?'success':'error');
    if(!await reviewPage.locator('#action-status').textContent().then(s=>s.includes(success?'TCP connection verified successfully':'TCP connection could not be verified')))throw new Error('Missing foreground probe outcome');
    const visible=await reviewPage.locator('#action-status').evaluate(el=>{
     const r=el.getBoundingClientRect();
     return document.getElementById('review').matches(':modal')&&r.top>=0&&r.bottom<=innerHeight&&r.left>=0&&r.right<=innerWidth&&el.contains(document.elementFromPoint(r.left+r.width/2,r.top+r.height/2));
    });
    if(!visible)throw new Error('Probe result is outside the viewport or behind the modal');
    if(await reviewPage.locator('#toast').isVisible())throw new Error('Probe outcome leaked to a background toast');
   }
  }
  await reviewPage.locator('#review .close').click();
  await reviewPage.getByRole('button',{name:'Open proposal'}).click();
  if(await reviewPage.locator('#action-status').getAttribute('data-status')!=='error')throw new Error('Reopened failed probe looks successful');
  if(errors.length)throw new Error(errors.join('\n'));
  console.log('Browser smoke passed: network scope, read-only demo, mobile layout, foreground probe progress/success/failure.');
 } finally {await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
