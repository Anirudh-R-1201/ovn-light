// SPDX-License-Identifier: Apache-2.0
// Start `ovn-light --demo` before running. Playwright is an optional dev tool.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH||undefined,args:process.env.NO_SANDBOX?['--no-sandbox']:[]});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.OVN_LIGHT_URL||'http://127.0.0.1:8080');
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
  if(errors.length)throw new Error(errors.join('\n'));
  console.log('Browser smoke passed: inferred CDN/UDN scope, explicit manual network choice, read-only demo, mobile layout.');
 } finally {await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
