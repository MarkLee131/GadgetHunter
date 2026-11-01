const {chromium}=require(require('node:path').resolve('.gadgethunter/tools/demo-video/node_modules/playwright'));
const fs=require('fs');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH});
 try{
 const page=await browser.newPage({viewport:{width:1280,height:720}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8876');await page.locator('.job-row').first().waitFor();
 await page.screenshot({path:'.gadgethunter/demo/ui-overview.png'});
 const rowTop=await page.locator('.job-row').first().evaluate(e=>e.getBoundingClientRect().top);assert(rowTop<300);
 const job=page.locator('.job-row').filter({hasText:'Static-analysis fixture · candidate scan'});
 await job.getByRole('button',{name:'Analyze candidates →'}).click();
 assert(await page.locator('#scan-form').isVisible());assert(!(await page.locator('#candidate-form').isVisible()));
 assert(await page.locator('#candidate-source').inputValue());assert(!(await page.locator('#scan-form [name="chains"]').isVisible()));
 await page.locator('[data-stage="candidate"]').click();
 await page.locator('#candidate-form [name="name"]').fill('Dependency review');
 await page.locator('#candidate-form [name="apps"]').setInputFiles('.gadgethunter/demo/fixture/static-analysis-fixture.jar');
 await page.screenshot({path:'.gadgethunter/demo/ui-scan.png'});
 await page.locator('#report-files').setInputFiles('demos/workbench/fixtures/saved-validation-report.json');
 await page.locator('#evidence-detail h2').waitFor();
 await page.locator('#notice button').click();
 await page.screenshot({path:'.gadgethunter/demo/ui-results.png'});
 assert((await page.locator('.result-item p').textContent()).includes('Example.sink'));
 const font=await page.locator('.edge code').first().evaluate(e=>getComputedStyle(e).fontSize);assert(parseFloat(font)>=14);
 await page.locator('#verdict-filter').selectOption('ERROR');assert(await page.getByText('No chains in this view.').isVisible());
 await page.locator('#verdict-filter').selectOption('FEASIBLE');assert(await page.locator('.edge').count()>0);
 const download=page.waitForEvent('download');await page.locator('#export-all').click();await(await download).saveAs('.gadgethunter/demo/ui-export.json');
 const report=JSON.parse(fs.readFileSync('.gadgethunter/demo/ui-export.json'));assert.equal(report.chain_id,0);assert(!('_origin'in report));
 await page.locator('[data-page="overview"]').click();await job.getByRole('button',{name:'Scan details',exact:true}).click();
 await page.locator('#candidate-dialog[open]').waitFor();await page.screenshot({path:'.gadgethunter/demo/ui-triage.png'});await page.locator('#close-candidate').click();
 const mobile=await browser.newPage({viewport:{width:390,height:844},isMobile:true});await mobile.goto('http://127.0.0.1:8876');await mobile.locator('.job-row').first().waitFor();
 for(const name of ['overview','scan','findings','guide']){
 await mobile.locator(`[data-page="${name}"]`).click();
 if(name==='findings')await mobile.locator('#report-files').setInputFiles('demos/workbench/fixtures/saved-validation-report.json');
 const dims=await mobile.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(dims.scroll<=dims.width,`${name} overflow: ${JSON.stringify(dims)}`);
 await mobile.screenshot({path:`.gadgethunter/demo/ui-mobile-${name}.png`,fullPage:true});
 }
 const hosted=await browser.newPage();await hosted.route('**/api/**',route=>route.fulfill({status:404,body:'not found'}));await hosted.goto('http://127.0.0.1:8876');await hosted.locator('[data-page="scan"]').click();await hosted.locator('#hosted-setup').waitFor();assert(!(await hosted.locator('.analysis-switch').isVisible()));await hosted.locator('#report-files').setInputFiles('demos/workbench/fixtures/saved-validation-report.json');await hosted.locator('.edge').first().waitFor();
 assert.deepEqual(errors,[]);console.log(JSON.stringify({rowTop,chainFont:font,desktop:true,mobile:true,importFilterExport:true,candidateTransition:true,hosted:true,errors}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
