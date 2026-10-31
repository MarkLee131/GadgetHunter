'use strict';
const $ = id => document.getElementById(id);
const state = {local:false, candidateConfigured:false, apiConfigured:false, jobs:[], reports:[], selected:null, imported:0, jobId:null, busy:false};
const verdicts = ['FEASIBLE','NOT_FEASIBLE','UNKNOWN','EARLY_STOP','ERROR'];
function el(tag, text, cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;}
function button(text, action, cls='text-button'){const node=el('button',text,cls);node.type='button';node.addEventListener('click',action);return node;}
function notice(text,error=false){$('notice').textContent=text;$('notice').className=error?'error':'';$('notice').hidden=false;}
function page(name){document.querySelectorAll('.page').forEach(p=>p.hidden=p.id!==`page-${name}`);document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===name));$('breadcrumb').textContent=`Workspace / ${{overview:'Overview',scan:'New analysis',findings:'Evidence explorer',guide:'Getting started'}[name]}`;if(name==='findings')renderFindings();window.scrollTo({top:0,behavior:'smooth'});}
async function api(path,body){const options=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-GadgetHunter':'1'},body:JSON.stringify(body)};const response=await fetch(`/api${path}`,options);let data;try{data=await response.json();}catch{throw new Error('The local analysis service returned an invalid response.');}if(!response.ok)throw new Error(data.error||`Request failed (${response.status})`);return data;}
function badge(value){return el('span',value,`verdict ${verdicts.includes(value)?value:['running','queued','failed','needs_review'].includes(value)?value:''}`);}
function empty(title,description,action){const node=el('div',undefined,'empty-state');node.append(el('span','⌁','empty-symbol'),el('h3',title),el('p',description));if(action)node.append(action);return node;}
function renderStats(){const counts=Object.fromEntries(verdicts.map(v=>[v,state.reports.filter(r=>r.conclusion.verdict===v).length]));const items=[['Chains in view',state.reports.length,'Current report selection'],['Feasible candidates',counts.FEASIBLE,'Require independent verification'],['Unresolved',counts.UNKNOWN,'Evidence still needed'],['Analysis errors',counts.ERROR,'Review execution details']];$('stats').replaceChildren(...items.map(([label,count,foot])=>{const card=el('div',undefined,'stat');card.append(el('span',label,'label'),el('i'),el('strong',String(count).padStart(2,'0')),el('small',foot));return card;}));$('nav-count').textContent=state.reports.length;}
function renderJobs(){
  updateCandidateSources();
  const list=$('jobs-list');list.replaceChildren();
  if(!state.jobs.length){list.append(empty(state.imported?'Reports are ready to explore.':'Start with a target, or a report.',state.imported?`${state.reports.length} chain records loaded in this browser session.`:'Create a local scan or import existing JSON reports. No sample findings are preloaded.',button(state.imported?'Explore evidence →':'Import reports ↥',()=>state.imported?page('findings'):$('report-files').click(),'button secondary')));return;}
  for(const job of state.jobs){
    const row=el('div',undefined,'job-row'),head=el('div',undefined,'job-header'),actions=el('div',undefined,'job-actions');
    head.append(el('span',job.name,'job-name'),badge(job.status));row.append(head);
    const active=['running','queued','cancelling'].includes(job.status);
    if(job.kind==='candidate'){
      row.append(el('p',`JAR scan · ${job.candidate_count||0} exported candidates · ${job.uploads?.length||0} JARs`,'job-meta'));
      if(active){const count=job.progress?.analyzed_methods;row.append(el('p',`${job.phase||'queued'}${count!=null?` · ${count.toLocaleString()} methods analyzed`:''}${job.elapsed_seconds!=null?` · ${Math.round(job.elapsed_seconds)} s`:''}`,'job-meta'));}
      actions.append(button('Scan details',()=>showCandidateReport(job.id)));
      if(!active&&job.candidate_count>0){
        actions.append(button('Analyze candidates →',()=>useCandidates(job.id)),button('Download chains ↓',()=>downloadCandidates(job.id)));
      }
      if(!active)actions.append(button('Run again',()=>jobAction(job.id,'retry')));
    }else{
      const max=Math.min(job.chain_count,job.max_chains);
      row.append(el('p',`${job.completed_chains} / ${max} chains · ${job.source_count} source files`,'job-meta'));
      const progress=el('div',undefined,'progress'),bar=el('span');bar.style.width=`${Math.min(100,100*job.completed_chains/Math.max(1,max))}%`;progress.append(bar);row.append(progress);
      if(job.candidate_coverage)row.append(el('p',`Candidate scan status: ${job.candidate_coverage} · bounded coverage`,'job-meta'));
      actions.append(button('View evidence →',()=>loadJob(job.id)));
      if(!active)actions.append(button('Resume',()=>jobAction(job.id,'resume')));
    }
    row.append(el('p',job.message||'','job-meta'));
    actions.append(button('Worker log',()=>showLog(job.id)));
    if(['running','queued'].includes(job.status))actions.append(button('Cancel',()=>jobAction(job.id,'cancel')));
    row.append(actions);list.append(row);
  }
}
function updateCandidateSources(){
  const select=$('candidate-source');if(document.activeElement===select)return;
  const selected=select.value,first=el('option','Upload a chains file');first.value='';select.replaceChildren(first);
  for(const job of state.jobs.filter(j=>j.kind==='candidate'&&j.candidate_count>0&&!['running','queued','cancelling'].includes(j.status))){const option=el('option',`${job.name} · ${job.candidate_count} candidates · ${job.status}`);option.value=job.id;select.append(option);}
  select.value=selected;if(!select.value)select.value='';candidateSourceChanged();
}
function candidateSourceChanged(){
  const id=$('candidate-source').value,input=$('scan-form').elements.chains;input.required=!id;input.disabled=!!id;$('selection-field').hidden=!id;
  const job=state.jobs.find(j=>j.id===id);
  $('candidate-source-note').textContent=job?`Using ${job.candidate_count} candidates. Original scan status: ${job.status}; bounded scans do not prove complete coverage.`:'Select a finished local scan, or upload an existing chains file.';
}
function useCandidates(id){page('scan');$('candidate-source').value=id;candidateSourceChanged();const job=state.jobs.find(j=>j.id===id);$('scan-form').elements.name.value=`${job?.name||'Candidates'} · analysis`;$('scan-form').scrollIntoView({behavior:'smooth',block:'start'});}
async function downloadCandidates(id){try{const response=await fetch(`/api/jobs/${id}/chains`);if(!response.ok)throw new Error('Candidate export is not ready.');const a=el('a');a.href=URL.createObjectURL(await response.blob());a.download=`gadgethunter-${id.slice(0,8)}-chains.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}catch(error){notice(error.message,true);}}
async function showCandidateReport(id){
  try{
    const data=await api(`/jobs/${id}/candidate-report`),box=$('candidate-detail');box.replaceChildren(el('h3',data.job.name),el('p',data.job.message));
    box.append(el('p','These are bounded static searches. Missing candidates do not establish that the target is safe.','subtle'));
    for(const phase of data.phases){
      const execution=phase.execution,inventory=phase.inventory,node=el('div');
      node.append(el('p',execution?`${execution.status} · ${execution.candidate_count} candidates · ${execution.elapsed_seconds||0} seconds`:'Prepared; search has not started.'));
      if(inventory)node.append(el('p',`${inventory.class_count} classes indexed (${inventory.application_class_count} application classes). Java ${inventory.target_java} native serialization.`));
      if(execution)node.append(el('p',`${execution.selected_root_count} callback roots · rules ${execution.rules_verified_loaded?'verified loaded':execution.status==='running'?'being checked':'not fully verified'} · heap ${execution.limits.heap_mb} MiB · time limit ${execution.limits.wall_seconds} s`));
      if(execution?.message)node.append(el('p',execution.message));
      const gaps={missing_rules:inventory?.unresolved_rules||[],missing_hierarchy_types:inventory?.unresolved_hierarchy_types||[],diagnostics:execution?.progress?.warnings||[],output_errors:execution?.output_errors||[]};
      const gapCount=Object.values(gaps).reduce((n,items)=>n+items.length,0);
      node.append(el('p',`${gapCount} unresolved input or execution diagnostics.`));
      if(gapCount){const details=el('details');details.append(el('summary','Inspect missing prerequisites and diagnostics'),el('pre',JSON.stringify(gaps,null,2)));node.append(details);}
      box.append(section(phase.name.toUpperCase(),node));
    }
    if(data.triage)box.append(section('REVIEW PRIORITY',renderTriage(data.triage)));
    if(data.enhancement){const e=data.enhancement,detail=el('div'),gaps=e.mode==='llm-gaps';detail.append(el('p',gaps?`${e.accepted_rules} model-proposed rules for unimplemented APIs (unverified hypotheses) · ${e.rejected_proposals.length} rejected proposals.`:`${e.accepted_rules} checked wrapper rules · ${e.rejected_proposals.length} rejected proposals.`),el('p',gaps?`${e.coverage.selected_gaps} of ${e.coverage.unimplemented_total} unimplemented methods sent to the model. Candidates that rely on these rules are labeled.`:`${e.coverage.selected_methods} methods selected; ${e.coverage.deferred_by_budget} deferred by the selection budget.`));box.append(section('RULE ENHANCEMENT',detail));}
    const raw=el('details');raw.append(el('summary','Coverage and candidate provenance record'),el('pre',JSON.stringify(data,null,2)));box.append(raw);$('candidate-dialog').showModal();
  }catch(error){notice(error.message,true);}
}
function triageTags(item){const tags=el('span',undefined,'triage-tags');tags.append(el('span',item.novelty,`triage-tag ${item.novelty}`),el('span',item.effect,'triage-tag effect'));if(item.blocked)tags.append(el('span','blocked','triage-tag blocked'));else if((item.mitigations||[]).length)tags.append(el('span','constrained','triage-tag constrained'));for(const family of item.families||[])tags.append(el('span',family,'triage-tag family'));return tags;}
function shortMethod(signature){const m=/<([\w.$]+): \S+ ([^\s(]+)\(/.exec(signature||'');return m?`${m[1].split('.').pop()}.${m[2]}`:signature;}
function renderTriage(t){
  const node=el('div'),s=t.summary;
  node.append(el('p',`${s.candidates} candidates form ${s.clusters} review clusters. ${s.novel_unblocked} are novel and not blocked on ${t.runtime||'an unknown runtime'}; ${s.known} match known public families; ${s.blocked} pass through routes the scanned bytecode blocks.`));
  if(t.class_facts!=='checked')node.append(el('p','Class facts were unavailable, so bytecode-backed mitigations are unverified rather than applied.','subtle'));
  node.append(el('p','“Novel” means no catalogued public family matched. It is a review priority, not a vulnerability verdict.','subtle'));
  const list=el('div',undefined,'triage-list'),seen=new Set();
  for(const item of t.top){if(seen.has(item.cluster_id))continue;seen.add(item.cluster_id);if(seen.size>40)break;
    const row=el('div',undefined,'triage-row');row.append(el('span',`#${item.rank+1}`,'triage-rank'));const body=el('div');body.append(triageTags(item),el('code',`${shortMethod(item.entry)} → … → ${shortMethod(item.sink)} · ${item.edge_count} edges`));
    for(const hit of item.mitigations||[])body.append(el('small',`${hit.status}: ${hit.summary}`));row.append(body);list.append(row);}
  node.append(list);return node;
}
function normalizeReport(raw,origin){const r=raw?.analysis_result||raw;if(!r||typeof r!=='object'||!Number.isInteger(r.chain_id)||!Array.isArray(r.original_chain)||!r.original_chain.every(x=>typeof x==='string')||!verdicts.includes(r.conclusion?.verdict))throw new Error(`${origin}: not a supported GadgetHunter chain result.`);return {...r,_origin:origin,_key:`${origin}:${r.chain_id}:${crypto.randomUUID()}`};}
function setReports(raw,origin){state.reports=raw.map(r=>normalizeReport(r,origin));state.selected=state.reports[0]?._key||null;renderStats();renderFindings();}
function renderFindings(){const query=$('search').value.trim().toLowerCase(),filter=$('verdict-filter').value;const found=state.reports.filter(r=>(!filter||r.conclusion.verdict===filter)&&(!query||`${r.chain_id} ${r.original_chain.join(' ')} ${r.conclusion.reasoning||''}`.toLowerCase().includes(query)));const list=$('results-list');list.replaceChildren();if(!found.length){list.append(empty('No chains in this view.',state.reports.length?'Change the verdict filter or search query.':'Import a chain JSON report or open the results of a local scan.'));$('evidence-detail').replaceChildren(empty('Evidence will appear here.','Select a chain to inspect its call edges, source context, constraints, and solver outcome.'));return;}if(!found.some(r=>r._key===state.selected))state.selected=found[0]._key;
for(const r of found){const node=button('',()=>{state.selected=r._key;renderFindings();},`result-item ${r._key===state.selected?'selected':''}`);const top=el('div',undefined,'result-top');top.append(el('strong',`CHAIN ${String(r.chain_id).padStart(3,'0')}`),badge(r.conclusion.verdict));const first=r.original_chain[0]||'No call edges';node.append(top,el('p',first.length>130?first.slice(0,130)+'…':first),el('small',`${r.original_chain.length} edges · ${Number(r.analysis_time||0).toFixed(1)} s`));list.append(node);}renderDetail(found.find(r=>r._key===state.selected));}
function section(title,content){const s=el('section',undefined,'evidence-section');s.append(el('h3',title),content);return s;}
function renderDetail(r){const box=$('evidence-detail');box.replaceChildren();const head=el('div',undefined,'panel-head');head.append(el('h2',`Chain ${r.chain_id}`),badge(r.conclusion.verdict));const body=el('div',undefined,'evidence-body');body.append(el('p',r.conclusion.reasoning||'No reasoning was recorded.','reasoning'));body.append(el('p',`Report: ${r._origin} · Solver: ${r.feasibility_analysis?.solver_status||'not run'}`,'subtle'));if(r.candidate_generation)body.append(el('p',`Candidate search: ${r.candidate_generation.status} · bounded coverage · origin: ${(r.candidate_generation.chain_phases||[]).join(', ')||'not recorded'}`,'subtle'));if(r.candidate_generation?.triage){body.append(triageTags(r.candidate_generation.triage));for(const hit of r.candidate_generation.triage.mitigations||[])body.append(el('p',`${hit.status}: ${hit.summary}`,'subtle'));}if(r.conclusion.verdict==='FEASIBLE')body.append(el('p','Constraint satisfaction is not proof of a working exploit or a previously unknown vulnerability. Verify the target environment and reachability independently.','subtle'));if(r.reused_from_chain!==undefined)body.append(el('p',`Reused analysis from chain ${r.reused_from_chain}; supporting logs belong to that chain.`,'subtle'));const edges=el('div');r.original_chain.forEach((edge,i)=>{const row=el('div',undefined,'edge');row.append(el('span',String(i+1).padStart(2,'0')),el('code',edge));edges.append(row);});body.append(section('CALL CHAIN',edges));const constraints=r.feasibility_analysis?.json_constraints;if(constraints&&Object.keys(constraints).length)body.append(section('EXTRACTED CONSTRAINTS',el('pre',JSON.stringify(constraints,null,2))));const error=r.error||r.feasibility_analysis?.error_message;if(error)body.append(section('UNRESOLVED EVIDENCE',el('pre',String(error))));const regions=Array.isArray(r.region_analysis?.regions)?r.region_analysis.regions:[];for(const region of regions){for(const gadget of (Array.isArray(region.gadgets)?region.gadgets:[])){if(gadget&&typeof gadget.source_code==='string'){const source=el('details');source.append(el('summary',gadget.method_signature||`Region ${region.region_id} source`),el('pre',gadget.source_code));body.append(source);}}}const raw=el('details');raw.append(el('summary','Full evidence record'),el('pre',JSON.stringify(cleanReport(r),null,2)));body.append(raw,button('Download chain JSON ↓',()=>download([r],`chain-${r.chain_id}.json`),'button secondary small'));box.append(head,body);}
function cleanReport(r){const {_key,_origin,...result}=r;return result;}
function download(reports,name){if(!reports.length){notice('Load reports before exporting.',true);return;}const blob=new Blob([JSON.stringify(reports.length===1?cleanReport(reports[0]):reports.map(cleanReport),null,2)],{type:'application/json'});const a=el('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
async function importFiles(files){try{const loaded=[];for(const file of files){if(file.size>25*1024*1024)throw new Error(`${file.name}: report exceeds 25 MiB.`);const data=JSON.parse(await file.text());for(const r of Array.isArray(data)?data:[data])loaded.push(normalizeReport(r,file.name));}if(!loaded.length)return;state.reports=loaded;state.selected=loaded[0]._key;state.imported=files.length;state.jobId=null;renderStats();renderJobs();page('findings');notice(`${loaded.length} chain records loaded. Imported files remain in this browser session and are not uploaded.`);}catch(error){notice(error.message,true);}finally{$('report-files').value='';}}
async function refresh(){if(!state.local||state.busy)return;state.busy=true;try{state.jobs=await api('/jobs');renderJobs();if(state.jobId){const current=await api(`/jobs/${state.jobId}/results`);const old=state.reports.find(r=>r._key===state.selected)?.chain_id;state.reports=current.map(r=>normalizeReport(r,`Local job ${state.jobId.slice(0,8)}`));state.selected=state.reports.find(r=>r.chain_id===old)?._key||state.reports[0]?._key||null;renderStats();if(!$('page-findings').hidden)renderFindings();}}catch(error){notice(`Connection issue: ${error.message}`,true);}finally{state.busy=false;}}
async function loadJob(id){try{state.jobId=id;state.imported=0;setReports(await api(`/jobs/${id}/results`),`Local job ${id.slice(0,8)}`);page('findings');}catch(error){notice(error.message,true);}}
async function jobAction(id,action){try{await api(`/jobs/${id}/${action}`,{});notice(action==='cancel'?'Cancellation requested. Completed evidence is retained.':action==='retry'?'A fresh candidate job was queued. Earlier evidence is retained.':'Job queued for resume.');await refresh();}catch(error){notice(error.message,true);}}
async function showLog(id){try{$('log-text').textContent=(await api(`/jobs/${id}/log`)).text;$('log-dialog').showModal();}catch(error){notice(error.message,true);}}
async function encodeFile(file){const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(binary);}
$('scan-form').addEventListener('submit',async event=>{
  event.preventDefault();const f=event.target.elements,source=f.sources.files[0],chains=f.chains.files[0],candidateId=f.candidate_job_id.value;
  if(!source||(!candidateId&&!chains))return;
  if(source.size>22*1024*1024||(!candidateId&&chains.size>8*1024*1024)){notice('Source ZIP must be at most 22 MiB and chains at most 8 MiB; total encoded request is limited to 32 MiB.',true);return;}
  $('start-scan').disabled=true;
  try{const data={name:f.name.value,model:f.model.value,max_chains:Number(f.limit.value),sources_zip:await encodeFile(source)};if(candidateId){data.candidate_job_id=candidateId;data.selection=f.selection.value;}else data.chains=await chains.text();if(new TextEncoder().encode(JSON.stringify(data)).length>32*1024*1024)throw new Error('Combined upload exceeds 32 MiB. Reduce the source bundle or chain file.');const job=await api('/jobs',data);notice(`Analysis “${job.name}” queued.`);page('overview');await refresh();}catch(error){notice(error.message,true);}finally{$('start-scan').disabled=!state.apiConfigured;}
});
$('candidate-form').addEventListener('submit',async event=>{
  event.preventDefault();const f=event.target.elements,apps=[...f.apps.files],libraries=[...f.libraries.files],all=[...apps,...libraries];
  if(!apps.length)return;
  if(all.length>64||all.reduce((sum,file)=>sum+file.size,0)>256*1024*1024){notice('Use at most 64 archives and 256 MiB combined.',true);return;}
  $('start-candidates').disabled=true;
  try{const encode=async files=>{const items=[];for(const file of files)items.push({name:file.name,data:await encodeFile(file)});return items;};const data={name:f.name.value,apps:await encode(apps),libraries:await encode(libraries),search_seconds:Number(f.seconds.value),heap_mb:Number(f.heap.value),enhancement:f.enhancement.value,model:f.model.value,profiles:{auto:['auto'],core:['native-core'],reflection:['native-core','jdk-propagation','modern-effects','reflection-boundaries']}[f.coverage.value]};const job=await api('/candidate-jobs',data);notice(`Candidate scan “${job.name}” queued.`);page('overview');await refresh();}catch(error){notice(error.message,true);}finally{$('start-candidates').disabled=!state.candidateConfigured;}
});
$('candidate-source').addEventListener('change',candidateSourceChanged);
$('enhancement-mode').addEventListener('change',event=>{const model=event.target.value.startsWith('llm');$('candidate-model-label').hidden=!model;$('candidate-privacy').textContent=event.target.value==='llm-gaps'?'Signatures of called APIs that have no implementation on your classpath, and the names of their callers, are sent to your model provider. Accepted rules are unverified and every candidate that relies on one is labeled.':model?'Selected target bytecode is sent to your model provider for proposals. Every proposed rule must pass independent validation.':'JARs and candidate results stay on this machine. Built-in and deterministic rules make no model calls.';});
$('close-candidate').addEventListener('click',()=>$('candidate-dialog').close());
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.page)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.go)));
$('import-top').addEventListener('click',()=>$('report-files').click());$('import-explorer').addEventListener('click',()=>$('report-files').click());$('report-files').addEventListener('change',event=>importFiles(event.target.files));$('export-all').addEventListener('click',()=>download(state.reports,'gadgethunter-results.json'));$('search').addEventListener('input',renderFindings);$('verdict-filter').addEventListener('change',renderFindings);$('close-log').addEventListener('click',()=>$('log-dialog').close());
async function init(){renderStats();renderJobs();renderFindings();try{const response=await fetch('/api/health');if(response.ok&&response.headers.get('content-type')?.includes('application/json')){const data=await response.json();state.local=data.mode==='local';state.candidateConfigured=!!data.candidate_configured;state.apiConfigured=!!data.api_configured;if(state.local&&!state.apiConfigured)notice('Built-in candidate scans need no API key. Set OPENAI_API_KEY and restart the server to enable model proposals and source analysis.');}}catch{}$('mode-text').textContent=state.local?'Local engine connected':'Browser report explorer';$('mode-description').textContent=state.local?'Scans run on this machine. Results stay in your workspace.':'Import and review reports privately in your browser. Start scans in the local workbench.';$('hosted-setup').hidden=state.local;$('scan-form').hidden=!state.local;$('candidate-form').hidden=!state.local;$('candidate-runtime-note').hidden=state.candidateConfigured;$('start-candidates').disabled=!state.candidateConfigured;$('start-scan').disabled=!state.apiConfigured;$('enhancement-mode').querySelectorAll('option[value^="llm"]').forEach(o=>o.disabled=!state.apiConfigured);$('job-mode').textContent=state.local?'LOCAL WORKER':'BROWSER SESSION';if(state.local){await refresh();setInterval(refresh,3000);}}
init();
