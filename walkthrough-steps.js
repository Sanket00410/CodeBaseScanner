/* Product-led walkthrough: four investigations, one shared report schema. */
(() => {
  const d=window.CSX_DEMO,steps=[];
  const add=(chapter,title,text,action={},duration=5)=>steps.push({chapter,title,text,action,duration});
  add('overview','Explain how risk became possible','CodeSentinelX connects a security finding to the change behind it: how it happened, when, who changed it, its blast radius and prevention. Explore a complete Aster Commerce example dataset.',{view:'overview'},9);
  add('overview','Five questions in one investigation','The overview answers all five questions using a permission-change example. Every answer is linked to a commit, deployment, snapshot or resource observation.',{highlight:'.incident-answers'},8);
  add('overview','Take the guided product tour','The guided tour moves through the four products, historical investigation and reports. Next, Previous and Close control the tour.',{click:'#start-tour'},5);
  add('overview','Next product chapter','Next opens Cloud Security and its responsible-change story.',{click:'#tour-next'},3);
  add('overview','Previous chapter','Previous returns to the overview.',{click:'#tour-prev'},3);
  add('overview','Explore independently','Close the coach to explore the completed assessments.',{click:'#tour-stop'},3);
  for(const p of d.products){
    const i=d.incidents[p.id];
    add(p.id,p.name+' investigation',i.how,{view:p.id},8);
    add(p.id,'Who, when and blast radius',i.actor+' introduced commit '+i.commit+'. Deployment '+i.deployment+' changed the environment at '+i.introduced+'. '+i.blast,{highlight:'.incident-answers'},9);
    add(p.id,'View the completed scan','The demo opens a completed assessment directly. All applicable engines contribute to the same product report; no setup or live scanning is needed to explore it.',{click:`[data-action="replay"][data-product="${p.id}"]`},6);
    for(const id of d.engineGroups[p.id]){
      const e=window.CSX_ENGINE_FIXTURES[p.id+':'+id];
      add(p.id,e.name+' evidence',e.summary+' Matching observations remain linked to one finding while preserving each engine source.',{click:`[data-engine="${p.id}:${id}"]`},4);
      add(p.id,'Return to combined scan results','Close the engine evidence and continue reviewing the assessment.',{click:'#close-evidence'},2);
    }
    add(p.id,'Unique findings and combined sources','Return to the product workspace. Matching engine observations are combined, so findings are not repeated for each tool.',{view:p.id},4);
    for(const f of d.findings.filter(f=>f.product===p.id)){
      add(p.id,f.title,f.fix,{click:`[data-finding="${f.id}"]`},6);
      add(p.id,'Read the responsible-change answers','The finding records why, how, introduction, first observation, actor, commit, deployment, root cause, blast radius and prevention.',{dialogBottom:true},4);
      add(p.id,'Review the finding','Mark reviewed updates this visit’s review state. Remediation still requires a validated fix and reassessment.',{click:`[data-reviewed="${f.id}"]`},2);
    }
    add(p.id,'Open the complete product report','This is one combined report for '+p.name+'. It uses the same investigation schema as the other three products.',{click:`[data-full-report="${p.id}"]`,wait:150},5);
    for(const [section,text] of [['executive_summary','The executive summary leads with the responsible change, combined finding counts and all five incident questions.'],['time_machine','Time Machine links the root cause, actor, commit and deployment to snapshots, timeline, comparison, path and investigator explanation.'],['sast','The shared SAST section retains source evidence when relevant to this report. Other product assessments have their own dedicated report.'],['dast','The shared DAST section retains observed application behavior and route scope when relevant.'],['cloud','The shared Cloud section retains resource, identity and change evidence when relevant.'],['ai','The shared AI Security section retains configuration and evaluation evidence when relevant.'],['framework_mapping','Framework coverage is presented separately from evidence and remediation. A report is not a compliance certification.'],['remediation_plan','The remediation plan specifies the finding, scoped action, responsible team and same-scope validation.'],['appendix','The appendix retains combined engine coverage, evidence sources and the demo dataset methodology.']])add(p.id,p.name+' report · '+section.replaceAll('_',' '),text,{reportSection:section},section==='time_machine'?9:4);
    add(p.id,'Close the report preview','The full report is also available as a standalone printable page.',{click:'#close-evidence'},2);
  }
  add('history','Attack Path Time Machine','Find how a change created the recorded path. The five questions are answered from explicit change, observation and deployment references.',{view:'time-machine'},7);
  for(const [value,label] of [['30days','30 days before detection'],['15days','15 days before detection'],['baseline','Last pre-change baseline'],['changed','After the responsible deployment']])add('history',label,'Compare the recorded configuration before and after the security-relevant change. The displayed state comes from the selected example snapshot.',{select:{id:'snapshot-date',value}},5);
  for(const p of d.products){
    add('history','Historical '+p.name+' investigation',d.incidents[p.id].how,{select:{id:'history-product',value:p.id}},5);
    for(let n=0;n<5;n++)add('history',['How did this happen?','When did this happen?','Who changed it?','What is the blast radius?','How do I prevent it again?'][n],'The investigator returns a grounded answer using the supplied change and assessment records for this product.',{select:{id:'investigator-question',value:String(n)},highlight:'#investigator-answer'},5);
  }
  add('history','Shadow Permission Detector','Cloud compares explicit grants with observed actions. Review unobserved permissions with the workload owner; missing observations do not prove disuse.',{select:{id:'history-product',value:'cloud'},highlight:'.panel:last-of-type'},7);
  add('reports','Four reports using one schema','The library contains exactly four reports: Cloud, SAST, DAST and AI Security. Each combines its engine sources. File formats are export choices within the report.',{view:'reports'},8);
  for(const r of window.CSX_REPORT_MANIFEST){
    add('reports',r.id.toUpperCase()+' report exports','Choose a file format for this same investigation. Changing the format does not create another report or alter its conclusions.',{highlight:`#report-format-${r.id}`},4);
    for(const format of r.formats)add('reports',r.id.toUpperCase()+' · '+format.toUpperCase(),`Export the same ${r.id.toUpperCase()} investigation as ${format.toUpperCase()}. The responsible-change answers, engine evidence, timeline and remediation are retained.`,{select:{id:`report-format-${r.id}`,value:format},click:`[data-export="${r.id}"]`},2);
  }
  add('supporting','What makes the workflow useful','Move from what is wrong to the change that introduced it, historical state, the recorded actor, affected scope and a prevention plan. The evidence remains together across all four products.',{view:'more'},8);
  add('finish','Explore CodeSentinelX','Choose a product, open its completed scan, inspect the change history and read its report. This is the complete illustrative product workflow, without engine setup or credentials.',{view:'overview'},7);
  let time=0;steps.forEach((s,index)=>{s.time=time;s.index=index;time+=s.duration;});window.CSX_WALKTHROUGH={steps,duration:time};
  const titles={overview:'The five incident questions',cloud:'Cloud: change, engines and report',sast:'SAST: source change, fixes and report',dast:'DAST: response change and report',ai:'AI Security: policy change and report',history:'Time Machine and grounded investigator',reports:'Four reports, one schema, export choices',supporting:'The investigation workflow',finish:'Explore the product'};
  d.chapters=[];for(const s of steps){let c=d.chapters.find(c=>c.id===s.chapter);if(!c){c={id:s.chapter,title:titles[s.chapter],time:s.time,duration:0,text:''};d.chapters.push(c);}c.duration+=s.duration;c.text+=s.title+': '+s.text+'\n';}
})();
