/* Four reports, one shared investigation schema. Export formats are file choices. */
(() => {
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const productName=id=>window.CSX_DEMO.products.find(p=>p.id===id).name;
  window.CSX_WORKFLOWS={
    jobs(_stage,scope){
      const engines=Object.values(window.CSX_ENGINE_FIXTURES).filter(e=>e.product===scope);
      const r=window.CSX_REPORT_MANIFEST.find(r=>r.id===scope);
      return `<div class="view-header"><div><h2>${esc(productName(scope))} · scan results</h2><p>One completed example assessment. Every engine contributes to the same product report.</p></div><span class="badge">Assessment complete</span></div><section class="panel"><div class="field-grid"><label>Product<select id="job-product">${window.CSX_DEMO.products.map(p=>`<option value="${p.id}" ${p.id===scope?'selected':''}>${p.name}</option>`).join('')}</select></label><label>Assessment scope<input readonly value="${esc(window.CSX_DEMO.incidents[scope].target)}"></label></div><div class="metrics">${[['Engine sources',r.engines],['Observations',r.observations],['Unique findings',r.findings],['Combined report',1]].map(([label,n])=>`<article class="metric"><span>${label}</span><strong>${n}</strong></article>`).join('')}</div><p id="job-state">Assessment complete · duplicate evidence combined · change history attached.</p><div class="table-wrap"><table><thead><tr><th>Engine</th><th>Job</th><th>Contribution</th><th></th></tr></thead><tbody>${engines.map(e=>`<tr><td><strong>${esc(e.name)}</strong></td><td>${esc(e.category)}</td><td>${esc(e.summary)}</td><td><button class="row-button" data-engine="${scope}:${e.engine_id}">Inspect evidence →</button></td></tr>`).join('')}</tbody></table></div><div class="detail-actions"><button class="button primary compact" data-full-report="${scope}">Read ${scope.toUpperCase()} report</button><button class="button compact" data-view="${scope}">Review findings →</button></div></section>`;
    },
    reports(){
      return `<div class="view-header"><div><h2>Four products. One report schema.</h2><p>One combined engine report per product: Cloud, SAST, DAST and AI Security. Choose a format when exporting.</p></div></div><div class="report-gallery">${window.CSX_REPORT_MANIFEST.map(r=>`<article class="report-card"><div class="panel-head"><h3>${esc(productName(r.id))}</h3><span class="badge">One combined report</span></div><p><strong>${esc(window.CSX_DEMO.incidents[r.id].title)}</strong></p><p>${r.engines} engine sources · ${r.observations} observations · ${r.findings} unique findings</p><p>How it happened · When it happened · Who changed it · Blast radius · Prevention</p><div class="detail-actions"><button class="button primary compact" data-full-report="${r.id}">Read entire report</button><a class="button compact" href="reports/${r.id}.html" target="_blank" rel="noopener">Open full page ↗</a></div><div class="report-export"><label>Export this report<select id="report-format-${r.id}">${r.formats.map(f=>`<option value="${f}">${({docx:'Word (DOCX)',xlsx:'Excel (XLSX)',md:'Markdown',txt:'Text',patch:'Fix patch'})[f]||f.toUpperCase()}</option>`).join('')}</select></label><button class="button compact" data-export="${r.id}">Download selected format ↓</button></div></article>`).join('')}</div>`;
    },
    openReport(id){
      if(!window.CSX_REPORT_MANIFEST.some(r=>r.id===id))return;
      const dialog=document.getElementById('evidence-dialog');
      document.getElementById('evidence-content').innerHTML=`<h2>${esc(productName(id))} · investigation report</h2><p>One investigation, including all engine evidence and the responsible-change timeline.</p><a class="row-button" href="reports/${id}.html" target="_blank" rel="noopener">Open full page ↗</a><iframe class="full-report" title="${esc(productName(id))} investigation report" src="reports/${id}.html"></iframe>`;
      dialog.showModal();dialog.scrollTop=0;
    },
    engine(key){
      const e=window.CSX_ENGINE_FIXTURES[key];if(!e)return;
      const findings=window.CSX_DEMO.findings.filter(f=>e.finding_ids.includes(f.id));
      document.getElementById('evidence-content').innerHTML=`<h2>${esc(e.name)} · assessment evidence</h2><p>${esc(e.category)} · Aster Commerce demo dataset</p><p>${esc(e.summary)}</p>${findings.map(f=>`<article class="panel"><h3>${esc(f.title)}</h3><p>${esc(f.resource)}</p><pre>${esc(f.code)}</pre><p><strong>Remediation:</strong> ${esc(f.fix)}</p><p><strong>Responsible change:</strong> ${esc(f.commit)} · ${esc(f.deployment)} · ${esc(f.who)}</p></article>`).join('')}<p>These observations are retained in the combined ${e.product.toUpperCase()} report.</p>`;
      const dialog=document.getElementById('evidence-dialog');dialog.showModal();dialog.scrollTop=0;
    },
    export(id){
      const format=document.getElementById('report-format-'+id)?.value;
      const report=window.CSX_REPORT_MANIFEST.find(r=>r.id===id);
      if(!report?.formats.includes(format))return;
      const a=document.createElement('a');a.href=`reports/${id}.${format}`;a.download=`codesentinelx-${id}-investigation.${format}`;a.click();
    }
  };
})();
