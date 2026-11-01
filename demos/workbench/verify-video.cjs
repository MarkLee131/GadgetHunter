const { chromium } = require(require('node:path').resolve('.gadgethunter/tools/demo-video/node_modules/playwright'));
const fs = require('fs');
const baseUrl=process.env.DEMO_PAGE_URL||'http://127.0.0.1:8877/';
(async () => {
  const browser = await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH});
  const desktop = await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[]; desktop.on('pageerror',e=>errors.push(e.message));
  await desktop.goto(baseUrl);
  await desktop.locator('a[href="#demo"]').click();
  await desktop.locator('#demo').screenshot({path:'.gadgethunter/demo/site-desktop.png'});
  const assets=await desktop.evaluate(()=>[...document.querySelectorAll('#demo [src],#demo [poster],#demo a[href]')].flatMap(e=>[e.getAttribute('src'),e.getAttribute('poster'),e.getAttribute('href')].filter(Boolean)));
  for(const asset of assets){const response=await desktop.request.get(new URL(asset,baseUrl).href);if(!response.ok())throw Error(`Asset ${asset}: ${response.status()}`);}
  const metadata=await desktop.locator('video').evaluate(async v=>{v.preload='auto';v.load();await new Promise((resolve,reject)=>{v.addEventListener('loadedmetadata',resolve,{once:true});v.addEventListener('error',()=>reject(Error('Video metadata error')),{once:true});});return {duration:v.duration,width:v.videoWidth,height:v.videoHeight,autoplay:v.autoplay,controls:v.controls};});
  if(metadata.width!==1920||metadata.height!==1080||metadata.duration<99||metadata.duration>115||metadata.autoplay||!metadata.controls)throw Error('Unexpected video metadata '+JSON.stringify(metadata));
  await desktop.locator('video').evaluate(async v=>{v.muted=true;await v.play();});
  await desktop.waitForFunction(()=>document.querySelector('video').currentTime>0.4);
  for(const t of [30,78,96]){await desktop.locator('video').evaluate(async (v,t)=>{v.currentTime=t;await new Promise(resolve=>v.addEventListener('seeked',resolve,{once:true}));},t);}
  await desktop.locator('video').evaluate(v=>v.pause());
  const track=await desktop.locator('video').evaluate(async v=>{const t=v.textTracks[0];t.mode='hidden';await new Promise(resolve=>setTimeout(resolve,400));return {language:t.language,cues:t.cues?.length};});
  if(track.cues!==11)throw Error('Missing caption cues '+JSON.stringify(track));
  const mobile=await browser.newPage({viewport:{width:390,height:844},isMobile:true,deviceScaleFactor:2});
  await mobile.goto(baseUrl+'#demo');
  await mobile.waitForFunction(()=>document.querySelector('video').readyState >= 1);
  await mobile.locator('#demo').screenshot({path:'.gadgethunter/demo/site-mobile.png'});
  const bounds=await mobile.locator('#demo').evaluate(e=>({width:e.clientWidth,scrollWidth:e.scrollWidth,videoWidth:e.querySelector('video').getBoundingClientRect().width,viewport:innerWidth}));
  if(bounds.scrollWidth>bounds.width||bounds.videoWidth>bounds.viewport)throw Error('Mobile overflow '+JSON.stringify(bounds));
  if(errors.length)throw Error(errors.join('\n'));
  const report={metadata,track,mobile:bounds,assetsChecked:assets.length,pageErrors:errors,playback:true,seekPositions:[30,78,96]};
  fs.writeFileSync('.gadgethunter/demo/browser-final-qa.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
