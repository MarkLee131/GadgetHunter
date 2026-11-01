const {chromium}=require(require('node:path').resolve('.gadgethunter/tools/demo-video/node_modules/playwright'));
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH});
 try {
 const page=await browser.newPage({viewport:{width:1280,height:800}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8876');
 await page.locator('[data-page="scan"]').click();
 await page.locator('[data-stage="source"]').click({timeout:2500});
 assert(await page.locator('#scan-form').isVisible());
 assert(!(await page.locator('#candidate-form').isVisible()));
 await page.locator('#scan-form [name="name"]').fill('Validation check');
 await page.locator('#scan-form [name="chains"]').setInputFiles('demos/workbench/fixtures/validation-chains.txt');
 await page.locator('#scan-form [name="sources"]').setInputFiles('.gadgethunter/demo/fixture/validation-sources.zip');
 await page.locator('#source-options summary').click();
 await page.locator('#scan-form [name="limit"]').fill('0');
 await page.locator('#source-options summary').click();
 await page.locator('#scan-form').evaluate(f=>f.reportValidity());
 assert(await page.locator('#source-options').evaluate(d=>d.open),'Invalid advanced field must be revealed');
 await page.locator('#scan-form [name="limit"]').fill('1');
 await page.locator('#source-options summary').click();
 let submitted;
 await page.route('**/api/jobs',async route=>{
  if(route.request().method()==='POST'){submitted=route.request().postDataJSON();await route.fulfill({json:{id:'test-ui',name:'Validation check'}});}else await route.continue();
 });
 await page.locator('#start-scan').evaluate(b=>b.disabled=false);
 await page.locator('#start-scan').click();
 await page.waitForFunction(()=>!document.querySelector('#page-overview').hidden);
 assert.equal(submitted.max_chains,1);assert.equal(submitted.model,'gpt-4.1');assert(submitted.sources_zip);assert(submitted.chains);
 await page.locator('[data-page="scan"]').click();
 await page.locator('[data-stage="candidate"]').click();
 assert(await page.locator('#candidate-form').isVisible());
 assert(!(await page.locator('#scan-form').isVisible()));
 assert.deepEqual(errors,[]);
 console.log('Stage selection, closed-setting submission and invalid-field recovery passed.');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
