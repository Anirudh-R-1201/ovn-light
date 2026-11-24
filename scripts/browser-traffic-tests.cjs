// SPDX-License-Identifier: Apache-2.0
module.exports=async function checkTrafficPicker(page){
  const options=await page.evaluate(()=>fetch('/api/traffic-test/options').then(r=>r.json()));
  await page.route('**/api/traffic-test/options',async route=>{
   await route.fulfill({json:{...options,nodes:[{name:'kind-worker'},{name:'kind-worker2'}]}});
  });
  let submitted;
  await page.route('**/api/traffic-test',async route=>{
   if(route.request().method()==='POST')submitted=route.request().postDataJSON();
   await route.fulfill({json:{enabled:true}});
  });
  await page.locator('#topology-detail').getByRole('button',{name:'Run traffic test'}).click();
  const testSource=page.locator('#traffic-test-source'),testDestination=page.locator('#traffic-test-destination');
  await page.locator('#traffic-test-submit:enabled').waitFor();
  if(await testSource.inputValue()!=='kind-worker'||await testDestination.inputValue()!=='kind-worker2')throw Error('Test picker lost topology link direction');
  await page.locator('#traffic-test-profile').selectOption('ib-read-bw');
  if(!await page.locator('#traffic-test-submit').isDisabled())throw Error('RDMA test enabled without a device resource');
  await page.locator('#traffic-test-profile').selectOption('http');
  await page.locator('#traffic-test-case').selectOption('POD_TO_CLUSTER_IP_TO_POD_SAME_NODE');
  await testSource.selectOption('kind-worker2');
  if(!await testDestination.isDisabled()||await testDestination.inputValue()!=='kind-worker2')throw Error('Same-node case has conflicting endpoints');
  const posted=page.waitForResponse(r=>r.url().endsWith('/api/traffic-test')&&r.request().method()==='POST');
  await page.locator('#traffic-test-submit').click();
  await posted;
  if(submitted.test!=='http'||submitted.case!=='POD_TO_CLUSTER_IP_TO_POD_SAME_NODE'||submitted.sourceNode!=='kind-worker2'||submitted.destinationNode!=='kind-worker2')throw Error('Submitted test differs from selection');
  await page.locator('#traffic-test-dialog .close').click();
  await page.unroute('**/api/traffic-test');
  await page.unroute('**/api/traffic-test/options');
};
