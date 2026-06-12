import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { pipelineApi, type DetectionVersion } from '@/api/client';
import { Header } from '@/components/Layout/Header';

type Tab = 'sources' | 'observables' | 'detections' | 'imports' | 'audit';
const input = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 outline-none focus:border-mitre-accent';

export function Pipeline() {
  const [tab,setTab]=useState<Tab>('sources');
  const {data:me}=useQuery({queryKey:['pipeline-me'],queryFn:pipelineApi.me});
  return <div className="flex flex-col h-full"><Header title="Intelligence Pipeline" />
    <div className="px-6 py-2 border-b border-gray-800 text-[11px] text-gray-500">Signed in as <span className="text-gray-300">{me?.name ?? 'local'}</span> · {(me?.roles ?? []).join(', ')} · Automated inputs remain pending until analyst review.</div>
    <div className="flex gap-5 px-6 border-b border-gray-700">{(['sources','observables','detections','imports','audit'] as Tab[]).map(item=><button key={item} onClick={()=>setTab(item)} className={`py-3 capitalize text-sm border-b-2 ${tab===item?'border-mitre-accent text-white':'border-transparent text-gray-500'}`}>{item}</button>)}</div>
    <div className="flex-1 overflow-y-auto p-6">{tab==='sources'&&<Sources/>}{tab==='observables'&&<Observables/>}{tab==='detections'&&<DetectionStudio/>}{tab==='imports'&&<Imports/>}{tab==='audit'&&<Audit/>}</div>
  </div>;
}

function Sources(){
  const qc=useQueryClient(); const {data=[]}=useQuery({queryKey:['pipeline-sources'],queryFn:pipelineApi.sources}); const {data:runs=[]}=useQuery({queryKey:['pipeline-runs'],queryFn:pipelineApi.runs});
  const [name,setName]=useState('');const[url,setUrl]=useState('');
  const create=useMutation({mutationFn:()=>pipelineApi.createSource({name,kind:'rss',url,enabled:true,interval_minutes:60,config:{}}),onSuccess:()=>{setName('');setUrl('');qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const run=useMutation({mutationFn:pipelineApi.runSource,onSuccess:()=>{qc.invalidateQueries({queryKey:['pipeline-runs']});qc.invalidateQueries({queryKey:['operations-intake']});qc.invalidateQueries({queryKey:['pipeline-observables']})}});
  return <div className="max-w-7xl mx-auto grid lg:grid-cols-[1fr_380px] gap-4"><Panel title="Collection Sources"><div className="grid md:grid-cols-[1fr_2fr_auto] gap-2 p-3"><input className={input} value={name} onChange={e=>setName(e.target.value)} placeholder="Feed name"/><input className={input} value={url} onChange={e=>setUrl(e.target.value)} placeholder="HTTPS RSS / Atom URL"/><button className="primary" disabled={!name||!url} onClick={()=>create.mutate()}>Add RSS</button></div>{data.map(row=><div key={row.id} className="flex items-center gap-3 p-3 border-t border-gray-800"><div className="flex-1"><b className="block text-sm text-gray-200">{row.name}</b><small className="block truncate text-gray-600">{row.kind.toUpperCase()} · {row.url}</small></div><button className="primary" onClick={()=>run.mutate(row.id)} disabled={run.isPending||row.kind!=='rss'}>Run</button></div>)}</Panel><Panel title="Recent Runs">{runs.map(row=><div key={row.id} className="p-3 border-b border-gray-800 text-xs"><b className={row.status==='complete'?'text-green-400':'text-red-400'}>{row.status}</b><span className="text-gray-500"> · {row.items_created} intake · {row.observables_created} observables</span>{row.error&&<p className="text-red-500 mt-1">{row.error}</p>}</div>)}</Panel></div>;
}

function Observables(){
  const qc=useQueryClient();const{data=[]}=useQuery({queryKey:['pipeline-observables'],queryFn:pipelineApi.observables});const[type,setType]=useState('domain');const[value,setValue]=useState('');
  const create=useMutation({mutationFn:()=>pipelineApi.createObservable({type,value,status:'new',confidence:0,tags:[],source_refs:[]}),onSuccess:()=>{setValue('');qc.invalidateQueries({queryKey:['pipeline-observables']})}});
  const enrich=useMutation({mutationFn:pipelineApi.enrich,onSuccess:()=>qc.invalidateQueries({queryKey:['pipeline-audit']})});
  return <div className="max-w-7xl mx-auto"><Panel title="Observable Workbench"><div className="grid md:grid-cols-[140px_1fr_auto] gap-2 p-3"><select className={input} value={type} onChange={e=>setType(e.target.value)}>{['domain','ipv4','sha256','md5','cve','url'].map(v=><option key={v}>{v}</option>)}</select><input className={input} value={value} onChange={e=>setValue(e.target.value)} placeholder="Observable value"/><button className="primary" disabled={!value} onClick={()=>create.mutate()}>Add</button></div><div className="grid lg:grid-cols-2">{data.map(row=><div key={row.id} className="flex gap-3 p-3 border-t border-gray-800"><span className="font-mono text-xs text-mitre-accent w-16">{row.type}</span><div className="flex-1 min-w-0"><b className="block truncate text-xs text-gray-300">{row.value}</b><small className="text-gray-600">{row.status} · confidence {row.confidence} · {row.source_refs.length} sources</small></div><button className="secondary" onClick={()=>enrich.mutate(row.id)}>Enrich</button></div>)}</div></Panel></div>;
}

function DetectionStudio(){
  const qc=useQueryClient();const{data=[]}=useQuery({queryKey:['pipeline-detection-versions'],queryFn:pipelineApi.versions});const[title,setTitle]=useState('');const[ttp,setTtp]=useState('T1059.001');const[format,setFormat]=useState('sigma');const[active,setActive]=useState<DetectionVersion|null>(null);
  const generate=useMutation({mutationFn:()=>pipelineApi.generate({title,technique_id:ttp,format,telemetry:['process_creation']}),onSuccess:row=>{setActive(row);qc.invalidateQueries({queryKey:['pipeline-detection-versions']})}});
  const validate=useMutation({mutationFn:()=>pipelineApi.validate(active!.format,active!.content),onSuccess:validation=>active&&setActive({...active,validation})});
  return <div className="max-w-7xl mx-auto grid lg:grid-cols-[380px_1fr] gap-4"><Panel title="Generate Controlled Skeleton"><div className="p-3 space-y-2"><input className={input} value={title} onChange={e=>setTitle(e.target.value)} placeholder="Detection title"/><input className={input} value={ttp} onChange={e=>setTtp(e.target.value.toUpperCase())}/><select className={input} value={format} onChange={e=>setFormat(e.target.value)}>{['sigma','kql','spl','eql'].map(v=><option key={v}>{v}</option>)}</select><button className="primary" disabled={!title||!ttp} onClick={()=>generate.mutate()}>Generate</button></div>{data.map(row=><button key={row.id} className="result" onClick={()=>setActive(row)}><b>{row.title}</b><small>{row.technique_id} · {row.format} · {row.created_by}</small></button>)}</Panel>{active?<Panel title={`${active.title} · ${active.format.toUpperCase()}`}><textarea className={`${input} h-[420px] font-mono rounded-none border-0`} value={active.content} onChange={e=>setActive({...active,content:e.target.value})}/><div className="p-3 flex items-center gap-3"><button className="primary" onClick={()=>validate.mutate()}>Validate</button><span className={active.validation.valid?'text-green-400 text-xs':'text-amber-400 text-xs'}>{active.validation.valid?'Structurally valid':'Needs review'} · {active.validation.warnings.length} warnings · {active.validation.errors.length} errors</span></div></Panel>:<Empty text="Generate or select a versioned rule skeleton. Placeholders and warnings must be resolved before production."/>}</div>;
}

function Imports(){
  const[kind,setKind]=useState<'stix'|'misp'|'atlas'>('stix');const[text,setText]=useState('{\n  \n}');const[result,setResult]=useState('');const run=useMutation({mutationFn:()=>pipelineApi.importJson(kind,JSON.parse(text)),onSuccess:data=>setResult(JSON.stringify(data,null,2)),onError:error=>setResult(String(error))});
  return <div className="max-w-5xl mx-auto"><Panel title="Reviewed Structured Import"><div className="p-3 space-y-3"><p className="text-xs text-gray-500">Paste a STIX bundle exported from TAXII, a MISP event, or MITRE ATLAS data. Imported reports enter pending intake.</p><select className={input} value={kind} onChange={e=>setKind(e.target.value as typeof kind)}><option value="stix">STIX / TAXII</option><option value="misp">MISP Event</option><option value="atlas">MITRE ATLAS</option></select><textarea className={`${input} h-72 font-mono`} value={text} onChange={e=>setText(e.target.value)}/><button className="primary" onClick={()=>run.mutate()}>Import and review</button>{result&&<pre className="p-3 bg-gray-950 text-xs text-gray-400 overflow-auto">{result}</pre>}</div></Panel></div>;
}

function Audit(){const{data=[]}=useQuery({queryKey:['pipeline-audit'],queryFn:pipelineApi.audit});return <div className="max-w-6xl mx-auto"><Panel title="Team Audit Trail">{data.map(row=><div key={row.id} className="grid md:grid-cols-[160px_180px_1fr] gap-3 p-3 border-b border-gray-800 text-xs"><span className="text-gray-600">{new Date(row.created_at).toLocaleString()}</span><span className="text-mitre-accent">{row.actor} · {row.action}</span><span className="text-gray-500">{row.object_type} {row.object_id}</span></div>)}</Panel></div>}
function Panel({title,children}:{title:string;children:React.ReactNode}){return <section className="rounded-lg border border-gray-800 bg-gray-900/60 overflow-hidden"><h2 className="text-sm font-semibold text-white px-3 py-3 border-b border-gray-800">{title}</h2>{children}</section>}
function Empty({text}:{text:string}){return <div className="rounded border border-gray-800 p-10 text-center text-sm text-gray-600">{text}</div>}
