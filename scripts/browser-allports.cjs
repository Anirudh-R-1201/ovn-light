// SPDX-License-Identifier: Apache-2.0
module.exports=async function checkCandidatesAndAllPorts(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 try{
  const state=await(await page.request.get(url+'/api/state')).json();
  const original=state.findings.find(f=>f.canRecommend),source=original.source,destination={...original.destination,port:0};
  const finding={...original,source:{node:source.node},destination,protocol:'',canRecommend:false,sourceContext:{address:'10.244.0.0/24',network:'default',totalCandidates:1,candidates:[{endpoint:source,observed:true,evidence:'Separate outgoing TCP activity toward the destination node was observed. Matching this activity to the drop is unconfirmed.'}]}};
  await page.route('**/api/state',route=>route.fulfill({json:{...state,findings:[finding]}}));
  await page.goto(url);
  await page.locator('.finding button').click();
  const details=await page.locator('#detail-body').textContent();
  if(!details.includes('10.244.0.0/24')||!details.includes('Node: '+source.node)||!details.includes('Unconfirmed'))throw new Error('Known source constraint/candidate uncertainty missing');
  const lines=await page.locator('#detail .endpoint').first().locator('span').evaluateAll(spans=>spans.map(s=>s.getBoundingClientRect()));
  if(lines.length<2||lines[1].top<lines[0].bottom)throw new Error('Source node ran into the address line');
  await page.getByRole('button',{name:'Choose the intended connection',exact:true}).click();
  if(await page.locator('#source').inputValue()!==''||await page.locator('#port').inputValue()!==''||await page.locator('#all-ports').isChecked())throw new Error('Unknown sender/port guessed automatically');
  await page.locator('#intent .close').click();
  await page.locator('.finding button').click();
  await page.getByRole('button',{name:'Review with this candidate →',exact:true}).click();
  if(JSON.parse(await page.locator('#source').inputValue()).uid!==source.uid||JSON.parse(await page.locator('#destination').inputValue()).uid!==destination.uid)throw new Error('Explicit candidate selection lost');
  if(!await page.locator('#intent-candidate-context').textContent().then(s=>s.includes('does not confirm')))throw new Error('Candidate presented as confirmed');
  if(await page.locator('#port').inputValue()!==''||await page.locator('#all-ports').isChecked())throw new Error('Candidate inferred a port');
  await page.locator('#all-ports').check();
  if(!await page.locator('#port').isDisabled())throw new Error('All ports still requires one numeric port');
  await page.locator('#protocol').selectOption('UDP');
  if(await page.locator('#all-ports-label').textContent()!=='All UDP ports')throw new Error('Port scope did not follow protocol');
  await page.locator('#protocol').selectOption('TCP');
  await page.locator('#all-ports').uncheck();
  if(await page.locator('#port').isDisabled()||!await page.locator('#port').evaluate(e=>e.required))throw new Error('Specific-port validation not restored');
  await page.locator('#all-ports').check();
  if(process.env.OVN_LIGHT_SCREENSHOTS)await page.screenshot({path:process.env.OVN_LIGHT_SCREENSHOTS+'/candidate-all-ports.png'});
  const response=page.waitForResponse(r=>r.url().endsWith('/api/plans')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Generate proposal →'}).click();
  const plan=await(await response).json();
  await page.waitForSelector('#review[open]');
  if(!plan.intent.allPorts||plan.intent.port!==0||!plan.manifests.includes('protocol: TCP')||plan.manifests.includes('port: 0'))throw new Error('Incorrect all-port proposal');
  if(!await page.locator('#review-body').textContent().then(s=>s.includes('Port scope: All TCP ports')&&s.includes('including future listeners')))throw new Error('Review hid broader allowance');
  await page.setViewportSize({width:390,height:844});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('All-port proposal overflows on mobile');
  await page.locator('#review .close').click();
  // An all-port allowance needs an explicit single-port test and must retain its applied status.
  const applied={...plan,status:'applied',applied:plan.objects.map(o=>({kind:o.kind,name:o.metadata.name})),verification:'Applied; connectivity has not been verified.'};
  await page.route('**/api/state',route=>route.fulfill({json:{...state,mode:'live',writesEnabled:true}}));
  await page.route('**/api/plans',route=>route.fulfill({json:[applied]}));
  let probes=0;
  await page.route('**/api/plans/*/verify',route=>{
   probes++;
   if(route.request().postDataJSON().port!==8080)throw new Error('Probe port was not explicit');
   return route.fulfill({json:{...applied,verificationPort:8080,verificationSucceeded:true,verification:'TCP connection established. Only this TCP port was tested; other ports were not verified.'}});
  });
  await page.reload();
  await page.locator('[data-page="changes"]').click();
  await page.getByRole('button',{name:'Open proposal',exact:true}).click();
  if(!await page.locator('.review-check').textContent().then(s=>s.includes('All TCP destination ports')))throw new Error('Review acknowledgement lost all-port scope');
  await page.locator('#verify-plan').click();
  if(probes!==0||!await page.locator('#action-status').textContent().then(s=>s.includes('Choose a listening TCP port')))throw new Error('Missing test port was guessed');
  await page.locator('#probe-port').fill('8080');
  await page.locator('#verify-plan').click();
  await page.waitForFunction(()=>document.querySelector('#action-status').dataset.status==='success');
  if(!await page.locator('#action-status').textContent().then(s=>s.includes('TCP port 8080 verified successfully')&&s.includes('other ports were not verified')))throw new Error('Single probe claimed all ports verified');
  if(await page.locator('#review-body > .badge').textContent()!=='applied')throw new Error('Whole plan incorrectly marked verified');
  if(!await page.locator('#action-status').evaluate(el=>{const r=el.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight;}))throw new Error('Test result is outside the foreground mobile view');
 }finally{await page.close()}
};
