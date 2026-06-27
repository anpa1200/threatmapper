import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  malwareGraphApi,
  type MalwareGraphDebugAssistant,
  type MalwareGraphDebuggerWorkspace,
  type MalwareGraphRuntimeDebugSession,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import {
  Empty,
  Info,
  Metric,
  Panel,
  RUNTIME_DEBUG_DISCLAIMER,
  TtpText,
  analysisTargets,
  caseIdentifier,
  caseTitle,
  field,
  malwareInput,
  primarySampleRef,
  readHiddenCases,
  shortLabel,
  statusColor,
  visibleJobs,
} from '@/pages/malwareShared';
import { IocLink } from '@/utils/ctiLinks';

export function DynamicAnalysis() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [jobId, setJobId]                         = useState(params.get('job_id') ?? '');
  const [sampleRef, setSampleRef]                 = useState(params.get('sample_ref') ?? '');
  const [disclaimerAccepted, setDisclaimer]       = useState(params.get('dynamic') === 'true');
  const [aiProvider, setAiProvider]               = useState(params.get('ai_provider') ?? 'local');
  const [session, setSession]                     = useState<MalwareGraphRuntimeDebugSession | null>(null);
  const [workspace, setWorkspace]                 = useState<MalwareGraphDebuggerWorkspace | null>(null);
  const [aiSummary, setAiSummary]                 = useState<MalwareGraphDebugAssistant | null>(null);
  const [autoStepping, setAutoStepping]           = useState(false);
  const [autoFunctionStepping, setAutoFunctionStepping] = useState(false);
  const [feedbackLoopRunning, setFeedbackLoopRunning] = useState(false);
  const [lastAiLoopStep, setLastAiLoopStep] = useState<number | null>(null);
  const [loopHistory, setLoopHistory] = useState<FeedbackLoopEntry[]>([]);

  const jobs     = useQuery({ queryKey: ['malwaregraph-jobs'],             queryFn: malwareGraphApi.jobs,      retry: false });
  const providers = useQuery({ queryKey: ['malwaregraph-providers'], queryFn: malwareGraphApi.providers, retry: false });
  const analysis = useQuery({ queryKey: ['malwaregraph-analysis', jobId], queryFn: () => malwareGraphApi.analysis(jobId), enabled: Boolean(jobId) });

  const currentJob = useMemo(() => jobs.data?.find(job => job.job_id === jobId), [jobId, jobs.data]);
  const targets    = useMemo(() => analysisTargets(analysis.data), [analysis.data]);

  useEffect(() => {
    if (jobId && readHiddenCases().has(jobId)) { setJobId(''); setSampleRef(''); }
  }, [jobId]);
  useEffect(() => {
    const visible = visibleJobs(jobs.data ?? []);
    if (!jobId && visible.length) setJobId(visible[0].job_id);
  }, [jobId, jobs.data]);
  useEffect(() => {
    if (!sampleRef && analysis.data) setSampleRef(primarySampleRef(analysis.data));
  }, [analysis.data, sampleRef]);
  useEffect(() => {
    const next = new URLSearchParams();
    if (jobId)              next.set('job_id',   jobId);
    if (sampleRef)          next.set('sample_ref', sampleRef);
    if (disclaimerAccepted) next.set('dynamic',  'true');
    next.set('ai_provider', aiProvider);
    setParams(next, { replace: true });
  }, [aiProvider, disclaimerAccepted, jobId, sampleRef, setParams]);

  // Auto-step effect: fires whenever current_step advances while auto-stepping.
  useEffect(() => {
    if (!autoStepping || !session || session.completed || stepSession.isPending) return;
    stepSession.mutate();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStepping, session?.current_step, session?.completed]);

  useEffect(() => {
    if (!autoFunctionStepping || !workspace || workspace.completed || stepWorkspace.isPending) return;
    stepWorkspace.mutate();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFunctionStepping, workspace?.step_count, workspace?.completed]);

  useEffect(() => {
    if (!feedbackLoopRunning) return;
    if (!session && !createSession.isPending) {
      createSession.mutate();
      return;
    }
    if (session && !workspace && !createWorkspace.isPending) {
      createWorkspace.mutate();
      return;
    }
    if (!workspace || stepWorkspace.isPending || runAiSummary.isPending || createWorkspace.isPending) return;
    if (lastAiLoopStep !== workspace.step_count) {
      runAiSummary.mutate({ loop: true });
      return;
    }
    if (!workspace.completed) {
      stepWorkspace.mutate();
      return;
    }
    setFeedbackLoopRunning(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [feedbackLoopRunning, session?.session_id, workspace?.session_id, workspace?.step_count, workspace?.completed, lastAiLoopStep]);

  const createSession = useMutation({
    mutationFn: () => malwareGraphApi.runtimeDebugSession(jobId, sampleRef, disclaimerAccepted, disclaimerAccepted),
    onSuccess: result => { setSession(result); setAutoStepping(false); setWorkspace(null); setAiSummary(null); setAutoFunctionStepping(false); setLastAiLoopStep(null); },
  });

  const stepSession = useMutation({
    mutationFn: () => malwareGraphApi.stepRuntimeDebugSession(session!.session_id),
    onSuccess: result => {
      setSession(result);
      if (result.completed) setAutoStepping(false);
    },
  });

  const createWorkspace = useMutation({
    mutationFn: () => malwareGraphApi.debugWorkspace(jobId, sampleRef, aiProvider, disclaimerAccepted, disclaimerAccepted),
    onSuccess: result => {
      setWorkspace(result);
      setAiSummary(result.ai_assistant ?? null);
      setAutoFunctionStepping(false);
      setLastAiLoopStep(null);
    },
  });

  const stepWorkspace = useMutation({
    mutationFn: () => malwareGraphApi.stepDebugWorkspace(workspace!.session_id),
    onSuccess: result => {
      setWorkspace(result);
      if (result.completed) setAutoFunctionStepping(false);
    },
  });

  const runAiSummary = useMutation({
    mutationFn: (_options?: { loop?: boolean }) => malwareGraphApi.debugWorkspaceAiAssistant(workspace!.session_id, aiProvider),
    onSuccess: (result, options) => {
      const snapshot = workspace;
      setAiSummary(result);
      setWorkspace(current => current ? { ...current, ai_assistant: result } : current);
      if (options?.loop && snapshot) {
        setLastAiLoopStep(snapshot.step_count);
        setLoopHistory(current => [
          ...current,
          buildFeedbackLoopEntry(current.length + 1, result, snapshot),
        ]);
      }
    },
  });

  const runManualAiSummary = useMutation({
    mutationFn: () => malwareGraphApi.debugWorkspaceAiAssistant(workspace!.session_id, aiProvider),
    onSuccess: result => {
      setAiSummary(result);
      setWorkspace(current => current ? { ...current, ai_assistant: result } : current);
    },
  });

  const isRunning = autoStepping || stepSession.isPending;
  const isFunctionRunning = autoFunctionStepping || stepWorkspace.isPending;
  const canStep   = Boolean(session && !session.completed && !isRunning);
  const canStepFunction = Boolean(workspace && !workspace.completed && !isFunctionRunning);

  function handleRunAll() {
    if (!canStep) return;
    setAutoStepping(true);
    stepSession.mutate();
  }

  function handleRunAllFunctions() {
    if (!canStepFunction) return;
    setAutoFunctionStepping(true);
    stepWorkspace.mutate();
  }

  function handleStartFeedbackLoop() {
    setFeedbackLoopRunning(true);
    setLoopHistory([]);
    setLastAiLoopStep(null);
  }

  return <div className="flex h-full flex-col">
    <Header title="Dynamic Analysis" />
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mx-auto grid max-w-7xl gap-4 xl:grid-cols-[340px_1fr]">

        <aside className="space-y-4">
          <Panel title="Runtime Target">
            <div className="space-y-3 p-3">
              <label className="block text-[10px] uppercase text-gray-600">Analysis case</label>
              <select value={jobId} onChange={e => { setJobId(e.target.value); setSampleRef(''); setSession(null); setWorkspace(null); setAiSummary(null); setAutoStepping(false); setAutoFunctionStepping(false); setFeedbackLoopRunning(false); setLoopHistory([]); setLastAiLoopStep(null); }} className={malwareInput}>
                {visibleJobs(jobs.data ?? []).map(job => (
                  <option key={job.job_id} value={job.job_id}>{caseTitle(job, undefined)} · {job.case_id ?? job.job_id}</option>
                ))}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">Runtime target</label>
              <select value={sampleRef} onChange={e => { setSampleRef(e.target.value); setSession(null); setWorkspace(null); setAiSummary(null); setAutoStepping(false); setAutoFunctionStepping(false); setFeedbackLoopRunning(false); setLoopHistory([]); setLastAiLoopStep(null); }} className={malwareInput}>
                {targets.map(target => <option key={target.id} value={target.id}>{target.label}</option>)}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">AI analysis provider</label>
              <select value={aiProvider} onChange={e => { setAiProvider(e.target.value); setAiSummary(null); }} className={malwareInput}>
                {(providers.data ?? []).map(provider => (
                  <option key={provider.provider} value={provider.provider}>
                    {provider.provider} · {provider.configured ? provider.model : provider.env_var}
                  </option>
                ))}
                {!(providers.data ?? []).length && <option value="local">local</option>}
              </select>
              <label className="flex items-start gap-3 rounded border border-amber-500/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                <input className="mt-0.5 shrink-0" type="checkbox" checked={disclaimerAccepted} onChange={e => setDisclaimer(e.target.checked)} />
                <span>{RUNTIME_DEBUG_DISCLAIMER}</span>
              </label>
              <button
                className="primary w-full"
                onClick={() => createSession.mutate()}
                disabled={!jobId || !sampleRef || !disclaimerAccepted || createSession.isPending}
              >
                {createSession.isPending ? 'Preparing...' : 'Prepare isolated runtime session'}
              </button>
              {session && !session.completed && <>
                <button className="primary w-full" onClick={handleRunAll} disabled={!canStep}>
                  {isRunning ? `Running step ${session.current_step + 1} / ${session.steps.length}...` : 'Run all steps'}
                </button>
                <button className="secondary-action w-full" onClick={() => stepSession.mutate()} disabled={!canStep}>
                  {stepSession.isPending ? 'Stepping...' : 'Step once'}
                </button>
                {autoStepping && (
                  <button className="secondary-action w-full" onClick={() => setAutoStepping(false)}>Stop auto-run</button>
                )}
              </>}
              {session && <>
                <button
                  className="primary w-full"
                  onClick={() => createWorkspace.mutate()}
                  disabled={!jobId || !sampleRef || !disclaimerAccepted || createWorkspace.isPending}
                >
                  {createWorkspace.isPending ? 'Loading functions...' : workspace ? 'Reload full function workflow' : 'Load full function workflow'}
                </button>
                {workspace && !workspace.completed && <>
                  <button className="primary w-full" onClick={handleRunAllFunctions} disabled={!canStepFunction}>
                    {isFunctionRunning ? `Running function ${workspace.step_count + 1} / ${workspace.function_traces.length}...` : 'Run all functions'}
                  </button>
                  <button className="secondary-action w-full" onClick={() => stepWorkspace.mutate()} disabled={!canStepFunction}>
                    {stepWorkspace.isPending ? 'Stepping function...' : 'Step function'}
                  </button>
                  {autoFunctionStepping && (
                    <button className="secondary-action w-full" onClick={() => setAutoFunctionStepping(false)}>Stop function run</button>
                  )}
                </>}
                {workspace && (
                  <button className="primary w-full" onClick={() => runManualAiSummary.mutate()} disabled={runManualAiSummary.isPending || feedbackLoopRunning}>
                    {runManualAiSummary.isPending ? 'AI analyzing dynamic results...' : aiSummary ? 'Re-run AI malware summary' : 'AI analyze dynamic results'}
                  </button>
                )}
                <button
                  className="primary w-full"
                  onClick={handleStartFeedbackLoop}
                  disabled={!jobId || !sampleRef || !disclaimerAccepted || feedbackLoopRunning || createSession.isPending || createWorkspace.isPending || stepWorkspace.isPending || runAiSummary.isPending}
                >
                  {feedbackLoopRunning ? 'AI feedback loop running...' : 'Run AI feedback loop'}
                </button>
                {feedbackLoopRunning && <button className="secondary-action w-full" onClick={() => setFeedbackLoopRunning(false)}>Stop AI feedback loop</button>}
              </>}
              {session?.completed && (
                <div className="rounded border border-green-600/30 bg-green-950/20 px-3 py-2 text-xs text-green-300">
                  Session complete — all steps executed
                </div>
              )}
              <button className="secondary-action w-full" onClick={() => navigate(`/malware-analysis?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}`)}>
                ← Back to case
              </button>
              {(createSession.error || stepSession.error || createWorkspace.error || stepWorkspace.error || runAiSummary.error || runManualAiSummary.error) && (
                <p className="text-xs text-red-300">{String(createSession.error ?? stepSession.error ?? createWorkspace.error ?? stepWorkspace.error ?? runAiSummary.error ?? runManualAiSummary.error)}</p>
              )}
            </div>
          </Panel>

          <Panel title="Case Context">
            {analysis.data ? <div className="grid gap-2 p-3 text-xs">
              <Info label="Case" value={caseTitle(currentJob, analysis.data)} />
              <Info label="Case ID" value={caseIdentifier(currentJob, analysis.data)} />
              <Info label="Job" value={analysis.data.job_id} />
              <Info label="Target" value={targets.find(t => t.id === sampleRef)?.label ?? sampleRef} />
            </div> : <Empty text="Select a case." />}
          </Panel>
        </aside>

        <main className="space-y-4">
          {session
            ? <DynamicSession
                session={session}
                isRunning={isRunning}
                workspace={workspace}
                isFunctionRunning={isFunctionRunning}
                aiSummary={aiSummary}
                aiPending={runAiSummary.isPending || runManualAiSummary.isPending}
                feedbackLoopRunning={feedbackLoopRunning}
                loopHistory={loopHistory}
                onOpenDebugger={() => navigate(`/malware-debug?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}${session.dynamic_enabled ? '&dynamic=true' : ''}`)}
              />
            : <div className="rounded border border-amber-500/40 bg-amber-950/30 p-4 text-sm font-semibold text-amber-100">
                Accept the disclaimer and click "Prepare isolated runtime session" to start.
              </div>
          }
        </main>
      </div>
    </div>
  </div>;
}

// ── Session view ──────────────────────────────────────────────────────────────

function DynamicSession({ session, isRunning, workspace, isFunctionRunning, aiSummary, aiPending, feedbackLoopRunning, loopHistory, onOpenDebugger }: {
  session: MalwareGraphRuntimeDebugSession;
  isRunning: boolean;
  workspace: MalwareGraphDebuggerWorkspace | null;
  isFunctionRunning: boolean;
  aiSummary: MalwareGraphDebugAssistant | null;
  aiPending: boolean;
  feedbackLoopRunning: boolean;
  loopHistory: FeedbackLoopEntry[];
  onOpenDebugger: () => void;
}) {
  const current = session.steps[session.current_step] ?? session.steps[0] ?? null;
  const done    = session.steps.filter(s => s.status === 'completed').length;
  const findings = extractAllFindings(session);

  return <>
    {/* Status strip */}
    <div className="grid gap-3 md:grid-cols-5">
      <Metric label="Mode" value={session.mode} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Dynamic" value={session.dynamic_enabled ? 'enabled' : 'off'} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Progress" value={`${done} / ${session.steps.length}`} tone={session.completed ? 'good' : isRunning ? 'warn' : 'default'} />
      <Metric label="Status" value={session.completed ? 'complete' : isRunning ? 'running' : current?.action ?? 'ready'} tone={session.completed ? 'good' : 'default'} />
      <Metric label="Findings" value={findings.total} tone={findings.total > 0 ? 'warn' : 'default'} />
    </div>

    {session.warning && (
      <div className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-100">{session.warning}</div>
    )}

    {/* Workflow graph */}
    <Panel title="Runtime Workflow Graph" actions={<button className="secondary-action" onClick={onOpenDebugger}>Open IDE debug</button>}>
      <RuntimeGraph session={session} />
    </Panel>

    <Panel title="Runtime Session Export">
      <pre className="max-h-80 overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(session, null, 2)}</pre>
    </Panel>

    {workspace
      ? <FullFunctionWorkflow workspace={workspace} isRunning={isFunctionRunning} aiSummary={aiSummary} aiPending={aiPending} feedbackLoopRunning={feedbackLoopRunning} loopHistory={loopHistory} />
      : <Panel title="Full Function Workflow">
          <Empty text="Load the full function workflow to view function traces, API hooks, memory/register state, event logs, graph export, and raw runtime snapshots." />
        </Panel>}

    {/* Findings summary — shown after any step completes */}
    {findings.total > 0 && <FindingsSummary findings={findings} />}

    {/* Per-step detail */}
    <Panel title="Step Results">
      <div className="divide-y divide-gray-800">
        {session.steps.map((step, index) => (
          <StepRow key={step.step_id} step={step} isCurrent={index === session.current_step} index={index} />
        ))}
      </div>
    </Panel>

    {/* Isolation */}
    <Panel title="Isolation Profile">
      <div className="grid gap-2 p-3 text-xs md:grid-cols-2">
        {Object.entries(session.isolation).map(([key, value]) => (
          <Info key={key} label={key.replace(/_/g, ' ')} value={field(value)} />
        ))}
      </div>
    </Panel>
  </>;
}

function FullFunctionWorkflow({ workspace, isRunning, aiSummary, aiPending, feedbackLoopRunning, loopHistory }: {
  workspace: MalwareGraphDebuggerWorkspace;
  isRunning: boolean;
  aiSummary: MalwareGraphDebugAssistant | null;
  aiPending: boolean;
  feedbackLoopRunning: boolean;
  loopHistory: FeedbackLoopEntry[];
}) {
  return <div className="space-y-4">
    <div className="grid gap-3 md:grid-cols-5">
      <Metric label="Target" value={workspace.target_name} />
      <Metric label="Functions" value={workspace.function_traces.length} tone={workspace.function_traces.length ? 'warn' : 'default'} />
      <Metric label="API hooks" value={workspace.api_hooks.length} tone={workspace.api_hooks.length ? 'warn' : 'default'} />
      <Metric label="Events" value={workspace.events.length} tone={workspace.events.length ? 'warn' : 'default'} />
      <Metric label="Function step" value={`${Math.min(workspace.step_count, workspace.function_traces.length)} / ${workspace.function_traces.length}`} tone={workspace.completed ? 'good' : isRunning ? 'warn' : 'default'} />
    </div>

    <Panel title="Execution Summary">
      <div className="grid gap-3 p-3 text-xs md:grid-cols-3">
        <Info label="Workspace" value={workspace.session_id} />
        <Info label="Mode" value={workspace.mode} />
        <Info label="Dynamic enabled" value={workspace.dynamic_enabled ? 'yes' : 'no'} />
        <Info label="Completed" value={workspace.completed ? 'yes' : 'no'} />
        <Info label="Current trace" value={workspace.current_trace_id} />
        <Info label="Risk summary" value={JSON.stringify(workspace.risk_summary)} />
      </div>
    </Panel>

    <AiDynamicSummary result={aiSummary} pending={aiPending} />

    <FeedbackLoopPanel running={feedbackLoopRunning} entries={loopHistory} workspace={workspace} />

    <div className="grid gap-4 xl:grid-cols-2">
      <KeyValuePanel title="Engine" data={workspace.engine} />
      <KeyValuePanel title="Binary" data={workspace.binary} />
      <KeyValuePanel title="Entrypoint" data={workspace.entrypoint ?? {}} />
      <KeyValuePanel title="Isolation" data={workspace.isolation} />
    </div>

    <Panel title="Function Results">
      <div className="divide-y divide-gray-800">
        {workspace.function_traces.map((trace, index) => (
          <FunctionTraceRow key={trace.trace_id} trace={trace} index={index} current={trace.trace_id === workspace.current_trace_id} />
        ))}
        {!workspace.function_traces.length && <Empty text="No function traces returned by MalwareGraph." />}
      </div>
    </Panel>

    <div className="grid gap-4 xl:grid-cols-2">
      <RecordsPanel title="API Hooks" records={workspace.api_hooks} />
      <RecordsPanel title="API Calls" records={workspace.api_calls} />
      <RecordsPanel title="Registers" records={workspace.registers} />
      <RecordsPanel title="Memory Regions" records={workspace.memory_regions} />
      <RecordsPanel title="Runtime Events" records={workspace.events} />
      <RecordsPanel title="IOC Leads" records={workspace.ioc_leads} />
      <RecordsPanel title="ATT&CK Leads" records={workspace.attack_leads} />
      <RecordsPanel title="Controls" records={workspace.controls} />
      <RecordsPanel title="Breakpoints" records={workspace.breakpoints} />
    </div>

    <Panel title="Graph Export">
      <div className="grid gap-3 p-3 md:grid-cols-3">
        <Metric label="Nodes" value={workspace.graph.nodes.length} />
        <Metric label="Edges" value={workspace.graph.edges.length} />
        <Metric label="Layout" value={workspace.graph.layout} />
      </div>
      <pre className="max-h-96 overflow-auto border-t border-gray-800 p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(workspace.graph, null, 2)}</pre>
    </Panel>

    <Panel title="Raw Workspace Export">
      <pre className="max-h-[520px] overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(workspace.export ?? workspace, null, 2)}</pre>
    </Panel>
  </div>;
}

interface FeedbackLoopEntry {
  iteration: number;
  timestamp: string;
  step: number;
  status: string;
  confidence: string;
  hypothesis: string;
  evidence: string[];
  gaps: string[];
  nextActions: string[];
}

function FeedbackLoopPanel({ running, entries, workspace }: {
  running: boolean;
  entries: FeedbackLoopEntry[];
  workspace: MalwareGraphDebuggerWorkspace;
}) {
  const currentTrace = workspace.function_traces[workspace.current_trace_index] ?? workspace.function_traces[workspace.step_count] ?? null;
  return <Panel title="AI Dynamic Feedback Loop">
    <div className="grid gap-3 p-3 md:grid-cols-4">
      <Metric label="Loop" value={running ? 'running' : entries.length ? 'paused' : 'ready'} tone={running ? 'warn' : entries.length ? 'good' : 'default'} />
      <Metric label="Iterations" value={entries.length} tone={entries.length ? 'good' : 'default'} />
      <Metric label="Function step" value={`${Math.min(workspace.step_count, workspace.function_traces.length)} / ${workspace.function_traces.length}`} tone={workspace.completed ? 'good' : running ? 'warn' : 'default'} />
      <Metric label="Current evidence" value={currentTrace?.name ?? 'none'} tone={currentTrace ? 'warn' : 'default'} />
    </div>
    <div className="border-t border-gray-800 p-3 text-xs">
      <div className="mb-2 text-[10px] uppercase text-gray-500">Loop policy</div>
      <div className="grid gap-2 md:grid-cols-3">
        <div className="rounded border border-gray-800 bg-gray-950 p-2 text-gray-400">Step one function/runtime point.</div>
        <div className="rounded border border-gray-800 bg-gray-950 p-2 text-gray-400">Run AI on the new evidence.</div>
        <div className="rounded border border-gray-800 bg-gray-950 p-2 text-gray-400">Continue until workflow completion or manual stop.</div>
      </div>
    </div>
    <div className="divide-y divide-gray-800">
      {entries.map(entry => <details key={`${entry.iteration}-${entry.timestamp}`} open={entry.iteration === entries.length}>
        <summary className="cursor-pointer px-3 py-2 text-xs hover:bg-gray-900/40">
          <span className="mr-2 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">#{entry.iteration}</span>
          <span className="text-gray-200"><TtpText value={entry.hypothesis || 'AI evidence review'} /></span>
          <span className="ml-2 text-[10px] uppercase text-gray-600">{entry.status} · confidence {entry.confidence}</span>
        </summary>
        <div className="grid gap-3 p-3 text-xs xl:grid-cols-3">
          <LoopList title="Evidence gained" items={entry.evidence} />
          <LoopList title="Remaining gaps" items={entry.gaps} />
          <LoopList title="Next actions" items={entry.nextActions} />
        </div>
      </details>)}
      {!entries.length && <Empty text="Start the AI feedback loop to build an iteration-by-iteration evidence trail." />}
    </div>
  </Panel>;
}

function LoopList({ title, items }: { title: string; items: string[] }) {
  return <div>
    <b className="text-gray-200">{title}</b>
    <div className="mt-2 max-h-44 overflow-y-auto rounded border border-gray-800 bg-gray-950">
      {items.length ? items.map((item, index) => <div key={`${item}-${index}`} className="border-b border-gray-900 px-2 py-1.5 text-[11px] leading-relaxed text-gray-400"><TtpText value={item} /></div>) : <div className="p-2 text-gray-600">none</div>}
    </div>
  </div>;
}

function buildFeedbackLoopEntry(iteration: number, result: MalwareGraphDebugAssistant, workspace: MalwareGraphDebuggerWorkspace): FeedbackLoopEntry {
  const assessment = result.assessment ?? {};
  const currentTrace = workspace.function_traces[workspace.current_trace_index] ?? workspace.function_traces[Math.max(0, workspace.step_count - 1)] ?? null;
  const functionItems = recordsToLines(assessment.function_analysis ?? assessment.malicious_or_suspicious_functions ?? assessment.suspicious_functions ?? []);
  const leadItems = recordsToLines([...(assessment.ttps ?? []), ...(assessment.iocs ?? []), ...(assessment.ioc_or_ttp_leads ?? [])]);
  const evidence = [
    currentTrace ? `Reviewed function ${currentTrace.name} at ${currentTrace.address} (${currentTrace.risk_level}, ${currentTrace.status}).` : '',
    ...functionItems,
    ...leadItems,
  ].filter(Boolean).slice(0, 16);
  const gaps = valuesToLines(assessment.validation_gaps ?? []);
  const nextActions = valuesToLines([
    ...(assessment.debug_next_steps ?? []),
    ...(assessment.api_hooks_to_prioritize ?? []).map(item => `Prioritize API hook: ${field(item)}`),
  ]);
  return {
    iteration,
    timestamp: new Date().toISOString(),
    step: workspace.step_count,
    status: workspace.completed ? 'completed' : 'in-progress',
    confidence: estimateConfidence(assessment, workspace),
    hypothesis: field(assessment.main_purpose ?? assessment.summary) || 'Dynamic behavior hypothesis pending',
    evidence,
    gaps,
    nextActions,
  };
}

function recordsToLines(items: Array<Record<string, unknown>>): string[] {
  return items.map(item => {
    const title = field(item.name ?? item.function ?? item.attack_id ?? item.value ?? item.type) || 'finding';
    const detail = field(item.evidence ?? item.reason ?? item.summary ?? item.description ?? item.behavior);
    return detail ? `${title}: ${detail}` : title;
  });
}

function valuesToLines(items: unknown[]): string[] {
  return items.map(item => field(item)).filter(Boolean);
}

function estimateConfidence(assessment: MalwareGraphDebugAssistant['assessment'], workspace: MalwareGraphDebuggerWorkspace): string {
  const gaps = assessment.validation_gaps?.length ?? 0;
  const suspicious = (assessment.malicious_or_suspicious_functions?.length ?? 0) + (assessment.suspicious_functions?.length ?? 0);
  if (workspace.completed && gaps === 0) return 'high';
  if (workspace.completed || suspicious > 0 || gaps <= 2) return 'medium';
  return 'low';
}

function FunctionTraceRow({ trace, index, current }: {
  trace: MalwareGraphDebuggerWorkspace['function_traces'][number];
  index: number;
  current: boolean;
}) {
  const [open, setOpen] = useState(current || index < 3);
  return <div className={current ? 'bg-mitre-accent/5 text-xs' : 'text-xs'}>
    <button type="button" onClick={() => setOpen(v => !v)} className="flex w-full items-start justify-between gap-3 p-3 text-left hover:bg-gray-900/40">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{index + 1}</span>
          <b className="font-mono text-gray-100">{trace.name}</b>
          <span className="font-mono text-[10px] text-gray-500">{trace.address}</span>
          <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ color: statusColor(trace.status), background: '#020617' }}>{trace.status}</span>
          <span className={`rounded px-1.5 py-0.5 text-[10px] ${trace.risk_level === 'high' ? 'bg-red-950/40 text-red-300' : trace.risk_level === 'medium' ? 'bg-amber-950/40 text-amber-300' : 'bg-gray-900 text-gray-500'}`}>{trace.risk_level}</span>
        </div>
        <p className="mt-1 break-words text-[11px] leading-relaxed text-gray-500"><TtpText value={trace.summary || trace.notes || 'No function summary returned.'} /></p>
      </div>
      <span className="shrink-0 text-gray-600">{open ? '▲' : '▼'}</span>
    </button>
    {open && <div className="space-y-3 border-t border-gray-800/60 p-3">
      <div className="grid gap-2 md:grid-cols-4">
        <Info label="Executed" value={trace.executed ? 'yes' : 'no'} />
        <Info label="Source" value={trace.source} />
        <Info label="Section" value={trace.section ?? 'unknown'} />
        <Info label="Confidence" value={`${Math.round(trace.confidence * 100)}%`} />
        <Info label="Instructions" value={String(trace.instruction_count)} />
        <Info label="MITRE" value={trace.mitre_technique || 'none'} />
        <Info label="RVA" value={trace.rva ?? 'n/a'} />
        <Info label="Entrypoint" value={trace.is_entrypoint ? 'yes' : 'no'} />
      </div>
      {trace.behaviors.length > 0 && <TokenList label="Behaviors" values={trace.behaviors} tone="warn" />}
      {trace.api_hooks && trace.api_hooks.length > 0 && <TokenList label="API hooks" values={trace.api_hooks} tone="default" />}
      {trace.strings_referenced.length > 0 && <TokenList label="Strings referenced" values={trace.strings_referenced} tone="default" />}
      {trace.calls_to.length > 0 && <TokenList label="Calls to" values={trace.calls_to} tone="default" />}
      {trace.called_from.length > 0 && <TokenList label="Called from" values={trace.called_from} tone="default" />}
      {trace.disassembly.length > 0 && <details className="rounded border border-gray-800">
        <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase text-gray-500 hover:text-gray-300">Disassembly ({trace.disassembly.length})</summary>
        <pre className="max-h-72 overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(trace.disassembly, null, 2)}</pre>
      </details>}
      <details className="rounded border border-gray-800">
        <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase text-gray-500 hover:text-gray-300">Snapshot and raw function JSON</summary>
        <pre className="max-h-96 overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(trace, null, 2)}</pre>
      </details>
    </div>}
  </div>;
}

function AiDynamicSummary({ result, pending }: { result: MalwareGraphDebugAssistant | null; pending: boolean }) {
  if (pending) return <Panel title="AI Malware Behavior Summary"><Empty text="AI is analyzing the dynamic function workflow and runtime evidence." /></Panel>;
  if (!result) return <Panel title="AI Malware Behavior Summary"><Empty text="Run AI analysis after loading the full function workflow to summarize what the malware does and which evidence supports it." /></Panel>;
  const assessment = result.assessment ?? {};
  return <Panel title={`AI Malware Behavior Summary${result.provider ? ` · ${result.provider}` : ''}`}>
    <div className="grid gap-4 p-3 text-xs xl:grid-cols-[minmax(0,1fr)_minmax(320px,420px)]">
      <div className="space-y-4">
        <SummaryBlock title="What This Malware Does" text={assessment.main_purpose ?? assessment.summary ?? assessment.raw_response} important />
        <SummaryBlock title="Behavior Summary" text={assessment.summary ?? assessment.raw_response} />
        <SummaryBlock title="Entrypoint Assessment" text={assessment.entrypoint_assessment} />
        <ObjectList title="Function-Level Analysis" items={assessment.function_analysis ?? []} limit={100} />
        <ObjectList title="Malicious / Suspicious Functions" items={assessment.malicious_or_suspicious_functions ?? assessment.suspicious_functions ?? []} />
      </div>
      <div className="space-y-4">
        <ObjectList title="ATT&CK Techniques" items={assessment.ttps ?? []} />
        <ObjectList title="IOCs" items={assessment.iocs ?? []} />
        <ObjectList title="IOC / TTP Leads" items={assessment.ioc_or_ttp_leads ?? []} />
        <ListBlock title="API Hooks To Prioritize" items={assessment.api_hooks_to_prioritize ?? []} mono />
        <ListBlock title="Validation Gaps" items={assessment.validation_gaps ?? []} />
        <ListBlock title="Recommended Next Steps" items={assessment.debug_next_steps ?? []} />
        {assessment.raw_response && <details className="rounded border border-gray-800">
          <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase text-gray-500 hover:text-gray-300">Raw AI response</summary>
          <pre className="max-h-80 overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{assessment.raw_response}</pre>
        </details>}
        {result.error && <div className="rounded border border-amber-500/30 bg-amber-950/20 p-3 text-amber-100">{result.error}</div>}
      </div>
    </div>
  </Panel>;
}

function SummaryBlock({ title, text, important = false }: { title: string; text: unknown; important?: boolean }) {
  return <section className={important ? 'rounded border border-mitre-accent/30 bg-mitre-accent/10 p-3' : ''}>
    <b className={important ? 'text-sm text-white' : 'text-gray-200'}>{title}</b>
    <p className="mt-2 whitespace-pre-wrap break-words text-[12px] leading-relaxed text-gray-300"><TtpText value={field(text) || 'No AI assessment returned for this section.'} /></p>
  </section>;
}

function ListBlock({ title, items, mono = false }: { title: string; items: unknown[]; mono?: boolean }) {
  return <div>
    <b className="text-gray-200">{title}</b>
    <div className={`mt-2 max-h-48 overflow-y-auto rounded border border-gray-800 bg-gray-950 ${mono ? 'font-mono' : ''}`}>
      {items.length ? items.slice(0, 60).map((item, index) => <div key={`${field(item)}-${index}`} className="border-b border-gray-900 px-2 py-1.5 text-[11px] leading-relaxed text-gray-400"><TtpText value={item} /></div>) : <div className="p-2 text-gray-600">none</div>}
    </div>
  </div>;
}

function ObjectList({ title, items, limit = 60 }: { title: string; items: Array<Record<string, unknown>>; limit?: number }) {
  return <div>
    <b className="text-gray-200">{title}</b>
    <div className="mt-2 max-h-72 overflow-y-auto rounded border border-gray-800 bg-gray-950">
      {items.length ? items.slice(0, limit).map((item, index) => <div key={index} className="border-b border-gray-900 p-2 text-[11px] leading-relaxed text-gray-400">
        <ObjectHeader item={item} />
        <div className="mt-1 space-y-1 text-gray-500">
          {objectDetailRows(item).map(row => <div key={row.key}>
            <span className="text-gray-600">{row.key}: </span>
            <span className={row.mono ? 'break-all font-mono text-gray-400' : 'text-gray-500'}><TtpText value={row.value} /></span>
          </div>)}
        </div>
      </div>) : <div className="p-2 text-gray-600">none</div>}
    </div>
  </div>;
}

function ObjectHeader({ item }: { item: Record<string, unknown> }) {
  const title = field(item.name ?? item.attack_id ?? item.value ?? item.address ?? item.function ?? item.type) || 'item';
  const route = objectRoute(item);
  const meta = [field(item.address), field(item.risk_level ?? item.risk), field(item.confidence)].filter(Boolean).join(' · ');
  return <div>
    {route ? <a className="break-all font-mono text-gray-200 hover:text-mitre-accent" href={route}>{title}</a> : <div className="break-all font-mono text-gray-200"><TtpText value={title} /></div>}
    {meta && <div className="mt-0.5 text-[10px] uppercase text-gray-600"><TtpText value={meta} /></div>}
  </div>;
}

function objectRoute(item: Record<string, unknown>) {
  const attackId = field(item.attack_id ?? (field(item.type) === 'ttp' ? item.value : ''));
  if (/^T\d{4}(?:\.\d{3})?$/.test(attackId)) return `/navigator?technique=${encodeURIComponent(attackId)}`;
  const value = field(item.value ?? item.indicator);
  if (value) return `/ioc-library?search=${encodeURIComponent(value)}`;
  return '';
}

function objectDetailRows(item: Record<string, unknown>) {
  const keys = [
    'role',
    'description',
    'reason',
    'evidence',
    'summary',
    'behavior',
    'ttps',
    'iocs',
    'next_debug_action',
    'type',
    'value',
  ];
  return keys
    .filter(key => item[key] !== undefined && item[key] !== null && field(item[key]) !== '')
    .map(key => ({
      key: key.replace(/_/g, ' '),
      value: field(item[key]),
      mono: ['value', 'iocs', 'ttps'].includes(key),
    }));
}

function TokenList({ label, values, tone }: { label: string; values: string[]; tone: 'default' | 'warn' }) {
  return <div>
    <div className="mb-1 text-[10px] uppercase text-gray-500">{label}</div>
    <div className="flex flex-wrap gap-1.5">
      {values.map((value, index) => (
        <span key={`${value}-${index}`} className={`max-w-full break-all rounded border px-1.5 py-0.5 font-mono text-[10px] ${tone === 'warn' ? 'border-amber-600/30 bg-amber-950/20 text-amber-200' : 'border-gray-700 bg-gray-900 text-gray-300'}`}><TtpText value={value} /></span>
      ))}
    </div>
  </div>;
}

function KeyValuePanel({ title, data }: { title: string; data: Record<string, unknown> }) {
  return <Panel title={title}>
    <div className="grid gap-2 p-3 text-xs">
      {Object.entries(data).map(([key, value]) => <Info key={key} label={key.replace(/_/g, ' ')} value={field(value)} />)}
      {!Object.keys(data).length && <Empty text="No data returned." />}
    </div>
  </Panel>;
}

function RecordsPanel({ title, records }: { title: string; records: Array<Record<string, unknown>> }) {
  return <Panel title={title}>
    <div className="max-h-96 overflow-y-auto divide-y divide-gray-800">
      {records.map((record, index) => (
        <details key={index} className="group">
          <summary className="cursor-pointer px-3 py-2 text-xs text-gray-300 hover:bg-gray-900/40">
            <span className="mr-2 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{index + 1}</span>
            {recordLabel(record)}
          </summary>
          <pre className="overflow-auto border-t border-gray-800 p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(record, null, 2)}</pre>
        </details>
      ))}
      {!records.length && <Empty text="No records returned." />}
    </div>
  </Panel>;
}

function recordLabel(record: Record<string, unknown>): string {
  return String(record.name ?? record.label ?? record.api ?? record.address ?? record.type ?? record.trace_id ?? record.event ?? record.value ?? JSON.stringify(record).slice(0, 120));
}

// ── Step row with extracted findings ─────────────────────────────────────────

function StepRow({ step, isCurrent, index }: {
  step: MalwareGraphRuntimeDebugSession['steps'][number];
  isCurrent: boolean;
  index: number;
}) {
  const [open, setOpen] = useState(step.status === 'completed');
  const snap = step.snapshot ?? {};
  const hasData = Object.keys(snap).length > 0;
  const stepFindings = extractStepFindings(snap);

  return <div className={`text-xs ${isCurrent ? 'bg-mitre-accent/5' : ''}`}>
    <button
      type="button"
      onClick={() => setOpen(v => !v)}
      className="flex w-full items-center justify-between gap-2 p-3 text-left hover:bg-gray-900/40"
    >
      <div className="flex items-center gap-3">
        <span className={`w-5 h-5 shrink-0 rounded-full flex items-center justify-center text-[10px] font-bold ${isCurrent ? 'bg-mitre-accent text-white' : step.status === 'completed' ? 'bg-green-800 text-green-200' : step.status === 'error' ? 'bg-red-900 text-red-200' : 'bg-gray-800 text-gray-400'}`}>
          {index + 1}
        </span>
        <div>
          <b className="text-gray-200">{step.action}</b>
          {step.target && <span className="ml-2 text-[10px] text-gray-500 font-mono">{shortLabel(step.target, 30)}</span>}
        </div>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {stepFindings.total > 0 && (
          <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-[10px] text-amber-300">{stepFindings.total} findings</span>
        )}
        <span style={{ color: statusColor(step.status) }} className="text-[11px]">{step.status}</span>
        <span className="text-gray-600">{open ? '▲' : '▼'}</span>
      </div>
    </button>

    {open && <div className="border-t border-gray-800/60 p-3 space-y-3">
      {step.notes && <p className="text-gray-500 leading-relaxed">{step.notes}</p>}
      {!hasData && step.status !== 'completed' && <p className="text-gray-600">No snapshot data yet.</p>}
      {hasData && <StepFindings findings={stepFindings} raw={snap} />}
    </div>}
  </div>;
}

// ── Findings extraction & display ─────────────────────────────────────────────

interface StepFindingsData {
  apiCalls:       string[];
  processes:      Array<{ name?: string; pid?: number | string; cmd?: string; [k: string]: unknown }>;
  fileOps:        Array<{ path?: string; operation?: string; [k: string]: unknown }>;
  registryOps:    Array<{ key?: string; operation?: string; [k: string]: unknown }>;
  networkConns:   Array<{ host?: string; ip?: string; port?: number | string; protocol?: string; [k: string]: unknown }>;
  iocs:           Array<{ type?: string; value?: string; [k: string]: unknown }>;
  strings:        string[];
  total:          number;
}

function extractStepFindings(snap: Record<string, unknown>): StepFindingsData {
  const apiCalls:     string[]                                       = asStrings(snap.api_calls ?? snap.api_trace ?? snap.calls);
  const processes:    StepFindingsData['processes']                  = asObjects(snap.processes ?? snap.spawned_processes);
  const fileOps:      StepFindingsData['fileOps']                   = asObjects(snap.file_operations ?? snap.file_ops ?? snap.files);
  const registryOps:  StepFindingsData['registryOps']               = asObjects(snap.registry_operations ?? snap.registry_ops ?? snap.registry);
  const networkConns: StepFindingsData['networkConns']              = asObjects(snap.network_activity ?? snap.network_connections ?? snap.connections ?? snap.network);
  const iocs:         StepFindingsData['iocs']                      = asObjects(snap.iocs ?? snap.indicators);
  const strings:      string[]                                       = asStrings(snap.captured_strings ?? snap.interesting_strings ?? snap.strings);
  const total = apiCalls.length + processes.length + fileOps.length + registryOps.length + networkConns.length + iocs.length + strings.length;
  return { apiCalls, processes, fileOps, registryOps, networkConns, iocs, strings, total };
}

interface AllFindings extends StepFindingsData {}

function extractAllFindings(session: MalwareGraphRuntimeDebugSession): AllFindings {
  const merged: AllFindings = { apiCalls: [], processes: [], fileOps: [], registryOps: [], networkConns: [], iocs: [], strings: [], total: 0 };
  for (const step of session.steps) {
    const f = extractStepFindings(step.snapshot ?? {});
    merged.apiCalls.push(...f.apiCalls);
    merged.processes.push(...f.processes);
    merged.fileOps.push(...f.fileOps);
    merged.registryOps.push(...f.registryOps);
    merged.networkConns.push(...f.networkConns);
    merged.iocs.push(...f.iocs);
    merged.strings.push(...f.strings);
  }
  merged.total = merged.apiCalls.length + merged.processes.length + merged.fileOps.length + merged.registryOps.length + merged.networkConns.length + merged.iocs.length + merged.strings.length;
  return merged;
}

function StepFindings({ findings, raw }: { findings: StepFindingsData; raw: Record<string, unknown> }) {
  const knownKeys = new Set(['api_calls','api_trace','calls','processes','spawned_processes','file_operations','file_ops','files','registry_operations','registry_ops','registry','network_activity','network_connections','connections','network','iocs','indicators','captured_strings','interesting_strings','strings']);
  const unknownEntries = Object.entries(raw).filter(([k]) => !knownKeys.has(k));

  return <div className="space-y-3">
    {findings.processes.length > 0 && <FindingsGroup label="Processes" count={findings.processes.length}>
      {findings.processes.map((p, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          <span className="font-mono text-gray-200">{String(p.name ?? p.cmd ?? JSON.stringify(p))}</span>
          {p.pid != null && <span className="text-gray-600">pid:{String(p.pid)}</span>}
        </div>
      ))}
    </FindingsGroup>}

    {findings.apiCalls.length > 0 && <FindingsGroup label="API Calls" count={findings.apiCalls.length}>
      <div className="flex flex-wrap gap-1.5">
        {findings.apiCalls.slice(0, 80).map((call, i) => (
          <span key={i} className="rounded border border-gray-700 bg-gray-900 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">{call}</span>
        ))}
        {findings.apiCalls.length > 80 && <span className="text-gray-600 text-[10px]">+{findings.apiCalls.length - 80} more</span>}
      </div>
    </FindingsGroup>}

    {findings.fileOps.length > 0 && <FindingsGroup label="File Operations" count={findings.fileOps.length}>
      {findings.fileOps.slice(0, 40).map((f, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {f.operation && <span className="shrink-0 rounded bg-blue-900/30 px-1.5 py-0.5 text-[9px] uppercase text-blue-300">{String(f.operation)}</span>}
          <span className="min-w-0 break-all font-mono text-[10px] text-gray-300">{String(f.path ?? JSON.stringify(f))}</span>
        </div>
      ))}
    </FindingsGroup>}

    {findings.registryOps.length > 0 && <FindingsGroup label="Registry" count={findings.registryOps.length}>
      {findings.registryOps.slice(0, 40).map((r, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {r.operation && <span className="shrink-0 rounded bg-purple-900/30 px-1.5 py-0.5 text-[9px] uppercase text-purple-300">{String(r.operation)}</span>}
          <span className="min-w-0 break-all font-mono text-[10px] text-gray-300">{String(r.key ?? JSON.stringify(r))}</span>
        </div>
      ))}
    </FindingsGroup>}

    {findings.networkConns.length > 0 && <FindingsGroup label="Network" count={findings.networkConns.length}>
      {findings.networkConns.slice(0, 40).map((n, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {n.protocol && <span className="shrink-0 text-[10px] text-gray-500 uppercase">{String(n.protocol)}</span>}
          <IocLink value={String(n.host ?? n.ip ?? JSON.stringify(n))} source="DynamicAnalysis" className="font-mono text-[10px] text-amber-300 hover:underline" />
          {n.port != null && <span className="text-gray-600">:{String(n.port)}</span>}
        </div>
      ))}
    </FindingsGroup>}

    {findings.iocs.length > 0 && <FindingsGroup label="IOC Indicators" count={findings.iocs.length}>
      {findings.iocs.map((ioc, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {ioc.type && <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[9px] text-gray-400">{String(ioc.type)}</span>}
          <IocLink value={String(ioc.value ?? JSON.stringify(ioc))} type={String(ioc.type ?? '')} source="DynamicAnalysis" className="break-all font-mono text-[10px] text-mitre-accent hover:underline" />
        </div>
      ))}
    </FindingsGroup>}

    {findings.strings.length > 0 && <FindingsGroup label="Captured Strings" count={findings.strings.length}>
      <div className="max-h-40 overflow-y-auto space-y-0.5">
        {findings.strings.slice(0, 100).map((s, i) => (
          <div key={i} className="rounded bg-gray-900/40 px-2 py-0.5 font-mono text-[10px] text-gray-400">{s}</div>
        ))}
      </div>
    </FindingsGroup>}

    {/* Unknown snapshot keys as collapsible raw JSON */}
    {unknownEntries.length > 0 && <details className="rounded border border-gray-800">
      <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase text-gray-500 hover:text-gray-300">Raw snapshot data</summary>
      <pre className="max-h-60 overflow-auto p-3 text-[10px] text-gray-500">{JSON.stringify(Object.fromEntries(unknownEntries), null, 2)}</pre>
    </details>}
  </div>;
}

function FindingsSummary({ findings }: { findings: AllFindings }) {
  return <Panel title="Dynamic Findings Summary">
    <div className="grid gap-3 p-3 md:grid-cols-4">
      <Metric label="API Calls"    value={findings.apiCalls.length}     tone={findings.apiCalls.length > 0 ? 'warn' : 'default'} />
      <Metric label="Processes"    value={findings.processes.length}    tone={findings.processes.length > 0 ? 'warn' : 'default'} />
      <Metric label="File Ops"     value={findings.fileOps.length}      tone={findings.fileOps.length > 0 ? 'warn' : 'default'} />
      <Metric label="Registry"     value={findings.registryOps.length}  tone={findings.registryOps.length > 0 ? 'warn' : 'default'} />
      <Metric label="Network"      value={findings.networkConns.length} tone={findings.networkConns.length > 0 ? 'bad' : 'default'} />
      <Metric label="IOCs"         value={findings.iocs.length}         tone={findings.iocs.length > 0 ? 'bad' : 'default'} />
      <Metric label="Strings"      value={findings.strings.length}      tone={findings.strings.length > 0 ? 'warn' : 'default'} />
      <Metric label="Total"        value={findings.total}               tone={findings.total > 0 ? 'warn' : 'good'} />
    </div>
    {findings.networkConns.length > 0 && (
      <div className="border-t border-gray-800 p-3">
        <div className="mb-2 text-[10px] uppercase text-gray-500">Network activity</div>
        <div className="flex flex-wrap gap-1.5">
          {findings.networkConns.map((n, i) => (
            <span key={i} className="rounded border border-amber-600/30 bg-amber-950/20 px-2 py-0.5 font-mono text-[10px] text-amber-300">
              {String(n.host ?? n.ip ?? JSON.stringify(n))}{n.port ? `:${String(n.port)}` : ''}
            </span>
          ))}
        </div>
      </div>
    )}
    {findings.iocs.length > 0 && (
      <div className="border-t border-gray-800 p-3">
        <div className="mb-2 text-[10px] uppercase text-gray-500">IOC indicators</div>
        <div className="flex flex-wrap gap-1.5">
          {findings.iocs.map((ioc, i) => (
            <IocLink key={i} value={String(ioc.value ?? JSON.stringify(ioc))} type={String(ioc.type ?? '')} source="DynamicAnalysis" className="rounded border border-red-600/30 bg-red-950/20 px-2 py-0.5 font-mono text-[10px] text-red-300 hover:border-red-400">
              {String(ioc.value ?? JSON.stringify(ioc))}
            </IocLink>
          ))}
        </div>
      </div>
    )}
  </Panel>;
}

function FindingsGroup({ label, count, children }: { label: string; count: number; children: React.ReactNode }) {
  return <div>
    <div className="mb-1.5 flex items-center gap-2">
      <span className="text-[10px] font-semibold uppercase text-gray-400">{label}</span>
      <span className="rounded bg-gray-800 px-1 py-0.5 text-[9px] text-gray-500">{count}</span>
    </div>
    <div className="space-y-1 text-[11px]">{children}</div>
  </div>;
}

// ── Workflow graph ─────────────────────────────────────────────────────────────

function RuntimeGraph({ session }: { session: MalwareGraphRuntimeDebugSession }) {
  const nodeWidth = 210; const nodeHeight = 48; const gap = 62; const x = 52; const width = 760;
  const height = 72 + session.steps.length * (nodeHeight + gap);

  return <div className="overflow-auto p-3">
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block rounded border border-gray-800 bg-gray-950">
      <defs>
        <marker id={`arrow-${session.session_id}`} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#64748b" />
        </marker>
      </defs>
      {session.steps.map((step, index) => {
        const y     = 34 + index * (nodeHeight + gap);
        const color = statusColor(step.status);
        const isCur = index === session.current_step;
        return <g key={step.step_id}>
          {index < session.steps.length - 1 && (
            <line x1={x + nodeWidth / 2} y1={y + nodeHeight} x2={x + nodeWidth / 2} y2={y + nodeHeight + gap - 8} stroke="#64748b" markerEnd={`url(#arrow-${session.session_id})`} />
          )}
          <rect x={x} y={y} width={nodeWidth} height={nodeHeight} rx="4" fill="#111827" stroke={isCur ? '#38bdf8' : color} strokeWidth={isCur ? 2.2 : 1.4} />
          <rect x={x} y={y} width="5" height={nodeHeight} rx="2" fill={color} />
          <text x={x + 14} y={y + 19} fill="#e5e7eb" fontSize="11" fontWeight="700">{shortLabel(step.action, 28)}</text>
          <text x={x + 14} y={y + 35} fill="#64748b" fontSize="10">{shortLabel(step.target ?? step.status, 30)}</text>
          <text x={x + nodeWidth + 18} y={y + 20} fill={color} fontSize="11">{step.status}</text>
          <title>{step.action} · {step.status} · {step.notes}</title>
        </g>;
      })}
    </svg>
  </div>;
}

// ── Utilities ──────────────────────────────────────────────────────────────────

function asStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter(item => typeof item === 'string') as string[];
}

function asObjects<T extends Record<string, unknown>>(value: unknown): T[] {
  if (!Array.isArray(value)) return [];
  return value.filter(item => item && typeof item === 'object' && !Array.isArray(item)) as T[];
}
