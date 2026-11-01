const {chromium}=require(require('node:path').resolve('.gadgethunter/tools/demo-video/node_modules/playwright'));const assert=require('node:assert/strict');const fs=require('fs');
(async()=>{const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH});try{
 const page=await browser.newPage();await page.goto('http://127.0.0.1:8876');await page.locator('.job-row').first().waitFor();
 const job=page.locator('.job-row').first();await job.locator('summary').click();await job.getByRole('button',{name:'Worker log'}).focus();await page.evaluate(()=>refresh());
 assert.equal(await page.evaluate(()=>document.activeElement.textContent),'Worker log','Polling should retain keyboard focus');
 await page.locator('#report-files').setInputFiles('demos/workbench/fixtures/saved-validation-report.json');
 let report=JSON.parse(fs.readFileSync('demos/workbench/fixtures/saved-validation-report.json'));report=report.analysis_result||report;
 await page.route('**/api/jobs/poll-test/results',route=>route.fulfill({json:[report]}));
 await page.evaluate(()=>loadJob('poll-test'));
 await page.getByText('Report details',{exact:true}).click();
 await page.evaluate(()=>refresh());
 assert(await page.getByText('Report details',{exact:true}).evaluate(s=>s.parentElement.open),'Unchanged results must retain open details');
 report={...report,analysis_time:999};await page.evaluate(()=>refresh());
 assert(await page.getByText('Report details',{exact:true}).evaluate(s=>s.parentElement.open),'Updated same-chain results must retain open details');
 console.log('Polling preserves job keyboard focus and evidence disclosures, for unchanged and updated results.');
}finally{await browser.close()}})().catch(e=>{console.error(e);process.exit(1)});
