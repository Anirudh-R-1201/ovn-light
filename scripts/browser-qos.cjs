// SPDX-License-Identifier: Apache-2.0
module.exports=async function checkQoS(browser,url,errors){
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
 try{
  await page.goto(url);await page.locator('[data-page="qos"]').click();await page.getByRole('button',{name:'Inspect QoS →'}).click();
  if(!await page.locator('#qos-detail').textContent().then(s=>s.includes('DSCP 20')&&s.includes('10000 kbps')&&s.includes('Observed OVN programming')))throw new Error('QoS desired/programmed context missing');
  await page.getByRole('button',{name:'Review value change →'}).click();await page.locator('[name="dscp"]').fill('24');await page.getByRole('button',{name:'Generate reviewed proposal'}).click();await page.waitForSelector('#review[open]');
  if(!await page.locator('#review-body').textContent().then(s=>s.includes('Current QoS before this change')&&s.includes('dscp: 24')&&s.includes('storefront/web-7b49')))throw new Error('QoS proposal lacks diff or affected source');
  if(await page.locator('#apply-plan').isVisible())throw new Error('Demo offered a live QoS write');await page.locator('#review .close').click();
  await page.locator('[data-page="topology"]').click();await page.waitForSelector('.topology-node');
  const before=await page.locator('#topology-zoom').textContent();await page.locator('#topology-zoom-in').click();if(await page.locator('#topology-zoom').textContent()===before)throw new Error('Zoom did not change');
  await page.locator('#topology-reset').click();if(await page.locator('#topology-zoom').textContent()!=='100%')throw new Error('Reset did not restore camera');
  const canvas=page.locator('.topology-viewport');await canvas.hover();await page.mouse.wheel(0,-100);await page.waitForFunction(()=>document.getElementById('topology-zoom').textContent!=='100%');
  await page.locator('.topology-filters summary').click();await page.locator('#topology-paths').selectOption('none');await page.waitForFunction(()=>document.querySelectorAll('.topology-link').length===0);if(!await page.locator('.topology-node').count())throw new Error('Hide paths hid all nodes');
  await page.locator('#topology-level').selectOption('namespaces');await page.waitForFunction(()=>document.querySelector('#topology-location').textContent.endsWith('/ Namespaces'));
  await page.setViewportSize({width:390,height:844});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('Topology controls overflow on mobile');
 }finally{await page.close()}
};
