import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, ArrowDownToLine, ArrowRight, Check, ChevronRight, CircleHelp, Clock3, Database, FileText, Fingerprint, Globe2, LayoutDashboard, Loader2, Plus, Radar, Search, Settings, ShieldCheck, ShieldAlert, Terminal, Wrench, X } from 'lucide-react';
import './style.css';

type Asset = {id:string;domain:string;label:string;created:string};
type Finding = {title:string;severity:string;confidence:string;protocol:string;evidence:string;remediation:string;rule_id:string};
type CheckResult = {protocol:string;status:string;assessment:string;query:string|null;records:string[];error?:string};
type Scan = {id:string;domain:string;selector:string;status:string;stage:string;created:string;finished:string|null;result:null|{checks:CheckResult[];findings:Finding[];limitations:string[]}};
type Workspace = {assets:Asset[];scans:Scan[]};
type Page = 'Overview'|'Assets'|'Scans'|'Findings'|'Remediation'|'Reports'|'Settings';
let csrf = '';
async function api(path:string, body?:unknown) {
  const response = await fetch('/api/'+path, body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-VulnX-CSRF':csrf}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
const time = (value:string) => new Date(value).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
const running = (scan:Scan) => ['running','queued'].includes(scan.status);
const nav = [{name:'Overview',icon:LayoutDashboard},{name:'Assets',icon:Database},{name:'Scans',icon:Radar},{name:'Findings',icon:ShieldAlert},{name:'Remediation',icon:Wrench},{name:'Reports',icon:FileText}] as const;

function App() {
  const [page,setPage]=useState<Page>('Overview');
  const [data,setData]=useState<Workspace>({assets:[],scans:[]});
  const [loaded,setLoaded]=useState(false);
  const [connected,setConnected]=useState(false);
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const [modal,setModal]=useState<'asset'|'scan'|null>(null);
  const [selected,setSelected]=useState<string|null>(null);
  const [readiness,setReadiness]=useState<{dns:boolean;nmap:boolean;pdf:boolean;network:string}|null>(null);
  const [search,setSearch]=useState('');
  const [severity,setSeverity]=useState('All severities');
  const [notice,setNotice]=useState('');
  const [formError,setFormError]=useState('');
  const refresh = async () => {try {setData(await api('state'));setLoaded(true);setConnected(true);} catch(e) {setConnected(false);throw e;}};
  useEffect(()=>{
    let active=true;
    async function start(){try {const session=await api('session');csrf=session.csrf;if(active)await refresh();} catch(e){if(active)setError((e as Error).message);}}
    void start();
    const timer=setInterval(()=>{if(csrf && active) void refresh().catch(e=>setError(e.message));},3000);
    return ()=>{active=false;clearInterval(timer);};
  },[]);
  useEffect(()=>{if(!notice)return;const timer=setTimeout(()=>setNotice(''),5000);return()=>clearTimeout(timer);},[notice]);
  useEffect(()=>{
    function key(e:KeyboardEvent){if(e.key==='Escape'){setModal(null);setSelected(null);}}
    window.addEventListener('keydown',key);return()=>window.removeEventListener('keydown',key);
  },[]);
  useEffect(()=>{
    if(!modal&&!selected)return;
    const previous=document.activeElement as HTMLElement|null;
    const dialog=document.querySelector<HTMLDialogElement>('dialog');
    const focusable=()=>Array.from(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled)')||[]);
    focusable()[0]?.focus();
    function trap(e:KeyboardEvent){
      if(e.key!=='Tab')return;
      const elements=focusable(),first=elements[0],last=elements[elements.length-1];
      if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}
      else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}
    }
    document.addEventListener('keydown',trap);
    return()=>{document.removeEventListener('keydown',trap);previous?.focus();};
  },[modal,selected]);
  const findings=data.scans.flatMap(scan=>(scan.result?.findings||[]).map(f=>({...f,scan})));
  const visible=findings.filter(f=>(severity==='All severities'||f.severity===severity)&&(f.title+' '+f.scan.domain).toLowerCase().includes(search.toLowerCase()));
  const detail=data.scans.find(s=>s.id===selected);
  function openModal(value:'asset'|'scan'){setFormError('');setModal(value);}
  async function submit(e:React.FormEvent<HTMLFormElement>){
    e.preventDefault();setBusy(true);setFormError('');
    const form=new FormData(e.currentTarget);
    try {
      if(modal==='asset') await api('assets',{domain:form.get('domain'),label:form.get('label'),authorized:form.get('authorized')==='on'});
      else await api('scans',{asset_id:form.get('asset_id'),selector:form.get('selector')});
      setModal(null);await refresh();setNotice(modal==='asset'?'Target added to your workspace.':'Assessment queued. Results will appear as checks finish.');
    }catch(e){setFormError((e as Error).message);}finally{setBusy(false);}
  }
  async function cancel(id:string){try{await api('cancel/'+id,{});await refresh();setNotice('Cancellation requested.');}catch(e){setError((e as Error).message);}}
  async function checkEnvironment(){setBusy(true);try{setReadiness(await api('readiness'));}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
  const empty=(title:string,description:string,Icon=Radar)=><div className="empty"><span className="empty-icon"><Icon size={25}/></span><h3>{title}</h3><p>{description}</p></div>;
  const assessmentTable=(items:Scan[])=><div className="table-wrap"><table><thead><tr><th>Target / profile</th><th>Status</th><th>Started</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{items.map(s=><tr key={s.id}><td><button className="text-button" onClick={()=>setSelected(s.id)}>{s.domain}</button><small>Email configuration</small></td><td><span className={'badge '+s.status}>{running(s)&&<Loader2 size={12} className="spin"/>}{s.status}</span><small>{s.stage}</small></td><td className="muted">{time(s.created)}</td><td><button className="icon-button" aria-label={'View assessment for '+s.domain} onClick={()=>setSelected(s.id)}><ChevronRight size={17}/></button></td></tr>)}</tbody></table></div>;
  const findingTable=(limit?:number)=><div className="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{visible.slice(0,limit).map((f,i)=><tr key={f.scan.id+f.rule_id+i}><td><button className="text-button" onClick={()=>setSelected(f.scan.id)}>{f.title}</button><small>{f.scan.domain} · {time(f.scan.created)}</small></td><td><span className={'severity '+f.severity.toLowerCase()}><i/>{f.severity}</span></td><td className="muted">{f.confidence}</td><td><button className="text-button jade" onClick={()=>setSelected(f.scan.id)}>Inspect <ArrowRight size={14}/></button></td></tr>)}</tbody></table></div>;
  return <div className="app-shell">
    <aside className="sidebar"><a className="brand" href="#" onClick={e=>{e.preventDefault();setPage('Overview');}}><span className="brand-mark">V</span>Vuln<span>X</span></a>
      <div className="workspace"><span className="workspace-icon"><Fingerprint size={19}/></span><div>Local workspace<small>Personal environment</small></div><span className="workspace-dot"/></div>
      <p className="nav-caption">WORKSPACE</p><nav>{nav.map(({name,icon:Icon})=><button key={name} className={page===name?'nav-link active':'nav-link'} onClick={()=>setPage(name)}><Icon size={18}/>{name}{name==='Findings'&&findings.length>0&&<span className="nav-count">{findings.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="local-note"><ShieldCheck size={19}/><strong>Your workspace. Your data.</strong><p>Assessments are stored on this Mac. Nothing is uploaded to GitHub.</p></div><button className={page==='Settings'?'nav-link active':'nav-link'} onClick={()=>setPage('Settings')}><Settings size={18}/>Settings</button><div className="runner"><span className={connected?'dot green':'dot'}/><div>{connected?'Local API connected':loaded?'Local API disconnected':'Connecting to local API'}<small>Single-user · v0.1</small></div></div></div>
    </aside>
    <main><header className="topbar"><div>Workspace <ChevronRight size={13}/> <span>{page}</span></div><span className="local-badge"><span className="dot"/> LOCAL DEPLOYMENT</span></header>
    <div className="page-content"><div className="page-heading"><div><div className="eyebrow">VULNX / ASSESSMENT WORKSPACE</div><h1>{page==='Overview'?'Security overview':page}</h1><p>{({Overview:'Evidence you can inspect. Findings you can understand.',Assets:'Your approved domains, organized in one place.',Scans:'Real assessments. Visible coverage. Traceable outcomes.',Findings:'Inspect the evidence behind every observation.',Remediation:'Follow an issue from discovery to a verified repair.',Reports:'Assessment records, ready to review and share.',Settings:'Know what is installed, connected and ready.'})[page]}</p></div><div className="heading-actions"><button className="button secondary" onClick={()=>setPage('Reports')}><ArrowDownToLine size={15}/>Reports</button><button className="button primary" onClick={()=>openModal('asset')}><Plus size={16}/>Add target</button></div></div>
    {error&&<div role="alert" className="alert error"><ShieldAlert size={17}/>{error}<button aria-label="Dismiss error" onClick={()=>setError('')}><X size={16}/></button></div>}
    {!loaded&&<div className="alert"><Loader2 className="spin" size={16}/>Loading the local workspace…</div>}
    {page==='Overview'&&<>
      <div className="metrics">{[{title:'Approved assets',value:loaded?data.assets.length:'—',note:'Domains in your workspace',icon:Database},{title:'Finding occurrences',value:loaded?findings.length:'—',note:'Across saved assessments · not deduplicated',icon:ShieldAlert},{title:'Assessments',value:loaded?data.scans.length:'—',note:'Includes incomplete and failed checks',icon:Activity},{title:'Verified fixes',value:'—',note:'Retest workflow coming next',icon:ShieldCheck}].map(({title,value,note,icon:Icon})=><section className="metric" key={title}><div>{title}<Icon size={17}/></div><strong>{value}</strong><small>{note}</small></section>)}</div>
      <section className="start-panel"><div className="start-intro"><div className="radar-art"><Radar size={29}/></div><div><span className="eyebrow jade">START WITH THE EVIDENCE</span><h2>{data.assets.length?'Your next assessment starts here.':'A clear view of your security starts here.'}</h2><p>Check a domain’s email configuration and inspect the actual DNS evidence.</p></div><button className="button primary" onClick={()=>openModal(data.assets.length?'scan':'asset')}>{data.assets.length?'New assessment':'Add your first target'}<ArrowRight size={16}/></button></div><div className="steps">{[{title:'Add an approved target',text:'Define the domain you can assess.'},{title:'Run the checks',text:'Query SPF, DMARC and a DKIM selector.'},{title:'Review the evidence',text:'Inspect records, coverage and guidance.'}].map((s,i)=><div key={s.title}><span>0{i+1}</span><div><strong>{s.title}</strong><small>{s.text}</small></div>{i<2&&<ChevronRight size={17}/>}</div>)}</div></section>
      <div className="overview-grid"><section className="panel"><div className="panel-heading"><h2><Activity size={17}/>Recent assessments</h2><button className="text-button muted" onClick={()=>setPage('Scans')}>View all <ArrowRight size={14}/></button></div>{data.scans.length?assessmentTable(data.scans.slice(0,4)):empty('No assessments yet','Your scan history and actual check outcomes will appear here.')}</section>
      <section className="panel"><div className="panel-heading"><h2><Terminal size={17}/>Scanner readiness</h2></div><div className="readiness">{[['DNS analyzer',readiness?(readiness.dns?'Executable found':'Not installed'):'Not checked'],['Nmap',readiness?(readiness.nmap?'Installed · integration pending':'Not installed'):'Not checked'],['Web / TLS scanners','Integration pending'],['PDF export',readiness?(readiness.pdf?'Dependency found':'Dependency missing'):'Not checked']].map(([label,status])=><div key={label}><span>{label}</span><small><span className="dot"/>{status}</small></div>)}</div><div className="panel-padding"><button className="button secondary full" disabled={busy} onClick={checkEnvironment}><Terminal size={14}/>{busy?'Checking…':'Check environment'}</button><p className="footnote">Availability checks do not prove network access or successful scanning.</p></div></section></div>
      <section className="panel"><div className="panel-heading"><h2><ShieldAlert size={17}/>Recent findings</h2><button className="text-button muted" onClick={()=>setPage('Findings')}>Explore findings <ArrowRight size={14}/></button></div>{findings.length?findingTable(5):empty('No findings recorded','Results appear only after checks run. No findings does not mean a target is secure.',ShieldCheck)}</section>
    </>}
    {page==='Assets'&&<section className="panel"><div className="panel-heading"><h2><Database size={17}/>Approved domains</h2><span className="count">{data.assets.length} assets</span></div>{!data.assets.length?empty('Add your first approved domain','Start with a domain you own or have permission to assess.',Globe2):<div className="asset-grid">{data.assets.map(a=><article className="asset-card" key={a.id}><span className="asset-icon"><Globe2 size={22}/></span><h3>{a.label}</h3><p>{a.domain}</p><small>Added {time(a.created)}</small><button className="button secondary full" onClick={()=>openModal('scan')}>Assess email configuration<ArrowRight size={14}/></button></article>)}</div>}</section>}
    {page==='Scans'&&<section className="panel"><div className="panel-heading"><h2><Radar size={17}/>Assessment history</h2><button className="button primary" onClick={()=>openModal(data.assets.length?'scan':'asset')}><Plus size={14}/>New assessment</button></div>{data.scans.length?assessmentTable(data.scans):empty('Ready when you are','Add an approved domain and launch an email assessment.')}</section>}
    {page==='Findings'&&<section className="panel"><div className="filters"><label className="search"><Search size={16}/><input aria-label="Search findings" placeholder="Search findings or domains…" value={search} onChange={e=>setSearch(e.target.value)}/></label><select aria-label="Filter severity" value={severity} onChange={e=>setSeverity(e.target.value)}>{['All severities','High','Medium','Low','Info'].map(s=><option key={s}>{s}</option>)}</select></div>{visible.length?findingTable():empty('No matching findings','Findings include the actual records and the reason a check flagged them.',ShieldAlert)}<div className="panel-padding footnote">This milestone shows occurrences across scans. Deduplication and CVE enrichment are not yet implemented.</div></section>}
    {page==='Remediation'&&<section className="panel">{empty('Verification is the next milestone','Finding-level repair tracking and comparable retests are not implemented yet. Existing findings already include remediation guidance.',Wrench)}<div className="center-action"><button className="button secondary" onClick={()=>setPage('Findings')}>Review remediation guidance<ArrowRight size={14}/></button></div></section>}
    {page==='Reports'&&<section className="panel"><div className="panel-heading"><h2><FileText size={17}/>Assessment exports</h2><span className="count">PDF / JSON</span></div>{!data.scans.filter(s=>!running(s)).length?empty('Reports start with an assessment','Completed, partial and failed assessments can be exported, with their limitations.',FileText):<div className="report-list">{data.scans.filter(s=>!running(s)).map(s=><article key={s.id}><span className="asset-icon"><FileText size={20}/></span><div><strong>{s.domain}</strong><small>{time(s.created)} · {s.status}</small></div><a className="button secondary" href={'/api/reports/'+s.id+'.json'} download>JSON</a><a className="button primary" href={'/api/reports/'+s.id+'.pdf'} download><ArrowDownToLine size={14}/>PDF</a></article>)}</div>}</section>}
    {page==='Settings'&&<div className="settings-grid"><section className="panel"><div className="panel-heading"><h2><Terminal size={17}/>Local environment</h2></div><div className="panel-padding"><p>Single-user loopback mode. Your browser talks to a local Python API; assets and assessments are stored in SQLite on this Mac.</p><button className="button secondary" disabled={busy} onClick={checkEnvironment}>Check installed tools</button>{readiness&&<div className="settings-results"><p>DNS executable: {readiness.dns?'found':'missing'}</p><p>Nmap executable: {readiness.nmap?'found; integration not implemented':'missing'}</p><p>PDF dependency: {readiness.pdf?'found':'missing'}</p><p>{readiness.network}</p></div>}</div></section><section className="panel"><div className="panel-heading"><h2><CircleHelp size={17}/>Current scope</h2></div><div className="panel-padding"><p>Working profile: basic email DNS configuration. Web scanning, network scanning, TLS, CVEs, user roles and verified retests are later milestones.</p><p>Do not expose this development server to a public network. Multi-user authentication and deployment hardening are not implemented.</p></div></section></div>}
    <footer><span><ShieldCheck size={13}/>Evidence-led assessments</span><span>VulnX 0.1 · Local development milestone</span></footer></div></main>
    {notice&&<div role="status" className="toast"><Check size={17}/>{notice}</div>}
    {modal&&<div className="overlay" onClick={()=>!busy&&setModal(null)}><dialog open className="modal" aria-labelledby="modal-title" onClick={e=>e.stopPropagation()}><div className="panel-heading"><h2 id="modal-title">{modal==='asset'?'Add an approved target':'New email assessment'}</h2><button className="icon-button" aria-label="Close dialog" onClick={()=>setModal(null)}><X size={19}/></button></div><form onSubmit={submit}><div className="panel-padding">{modal==='asset'?<><label>Domain<input autoFocus name="domain" placeholder="your-domain.com" required maxLength={253}/></label><label>Display name <span className="muted">optional</span><input name="label" placeholder="Organization website" maxLength={80}/></label><label className="checkbox"><input name="authorized" type="checkbox" required/><span>I own this domain or have permission to assess its email DNS configuration.</span></label></>:<><label>Approved domain<select autoFocus name="asset_id" required>{data.assets.map(a=><option key={a.id} value={a.id}>{a.domain}</option>)}</select></label><label>DKIM selector <span className="muted">optional</span><input name="selector" placeholder="Provided by your mail administrator" pattern="[A-Za-z0-9_-]+" maxLength={63}/></label><p className="footnote">Without a selector, DKIM is marked not assessed. This profile queries DNS; it does not send emails or prove authentication.</p></>}{formError&&<div className="alert error" role="alert">{formError}</div>}</div><div className="modal-actions"><button type="button" className="button secondary" onClick={()=>setModal(null)}>Cancel</button><button className="button primary" disabled={busy}>{busy?<Loader2 size={16} className="spin"/>:modal==='asset'?<Plus size={16}/>:<Radar size={16}/>} {modal==='asset'?'Add target':'Start assessment'}</button></div></form></dialog></div>}
    {detail&&<div className="overlay" onClick={()=>setSelected(null)}><dialog open className="modal detail" aria-labelledby="detail-title" onClick={e=>e.stopPropagation()}><div className="panel-heading"><div><h2 id="detail-title">{detail.domain}</h2><small>Email configuration · {time(detail.created)}</small></div><button autoFocus className="icon-button" aria-label="Close assessment" onClick={()=>setSelected(null)}><X size={19}/></button></div><div className="panel-padding"><div className="detail-meta"><span className={'badge '+detail.status}>{detail.status}</span><span>{detail.stage}</span>{running(detail)&&<button className="button secondary" onClick={()=>cancel(detail.id)}>Cancel assessment</button>}</div>{detail.result?.checks.map(c=><section className="check-card" key={c.protocol}><div><h3>{c.protocol}</h3><span className={'badge '+(c.status==='error'?'failed':c.status==='skipped'?'queued':'completed')}>{c.assessment}</span></div><small>{c.query||'No selector supplied'}</small>{c.records.map((r,i)=><pre key={i}>{r}</pre>)}{c.error&&<pre className="error-text">{c.error}</pre>}</section>)}{detail.result?.findings.map((f,i)=><section className="check-card" key={i}><span className={'severity '+f.severity.toLowerCase()}><i/>{f.severity} · {f.confidence} confidence</span><h3>{f.title}</h3><pre>{f.evidence}</pre><p>{f.remediation}</p></section>)}{detail.result&&<div className="limitations"><h3>Coverage & limitations</h3>{detail.result.limitations.map(l=><p key={l}>{l}</p>)}</div>}{!detail.result&&!running(detail)&&<p>No result was produced. This assessment does not establish the target’s security.</p>}</div>{!running(detail)&&<div className="modal-actions"><a className="button secondary" href={'/api/reports/'+detail.id+'.json'} download>Export JSON</a><a className="button primary" href={'/api/reports/'+detail.id+'.pdf'} download><ArrowDownToLine size={14}/>Export PDF</a></div>}</dialog></div>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
