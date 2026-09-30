"use client";

import { useState } from "react";
import { ArrowRight, CheckCircle2, ShieldAlert, Copy, Loader2, Globe2, Sparkles } from "lucide-react";

type Finding = { name: string; status: "pass" | "warn" | "fail"; detail: string; category: "security" | "reliability" | "ux" | "seo" | "other"; penalty?: number };
type Result = { score: number; verdict: string; finalUrl: string; redirects: number; durationMs: number; fetchDurationMs: number; aiDurationMs: number; scannedAt: string; penaltyTotal: number; categoryPenalties: Record<"security" | "reliability" | "ux" | "seo" | "other", number>; summary: string; findings: Finding[]; fixPrompt: string; aiUsed: boolean; aiStatus: string };


export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function scan() {
    setError("");
    setResult(null);
    if (!/^https?:\/\//i.test(url.trim())) {
      setError("Enter a full public URL starting with https://");
      return;
    }
    setLoading(true);
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: url.trim() }) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const message = data.error || (r.status === 429 ? "Too many scans. Please wait and try again." : "Scan failed.");
        throw new Error(message);
      }
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen overflow-hidden">
      <div className="mx-auto max-w-6xl px-5 sm:px-8">
        <header className="flex items-center justify-between py-6">
          <div className="flex items-center gap-2 font-semibold tracking-tight"><span className="grid h-8 w-8 place-items-center rounded-lg bg-white text-black"><Sparkles size={16}/></span>LaunchLens</div>
          <span className="hidden text-sm text-zinc-500 sm:block">Public launch-readiness scanner</span>
        </header>

        <section className="mx-auto max-w-4xl pb-16 pt-16 text-center sm:pt-24">
          <div className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/70 px-3 py-1.5 text-xs text-zinc-400"><Globe2 size={13}/> Scan any public web app</div>
          <h1 className="text-4xl font-semibold tracking-[-0.04em] sm:text-6xl">Find launch risks before your users do.</h1>
          <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-zinc-400 sm:text-lg">LaunchLens checks observable security, reliability and UX signals from your public URL and turns the findings into an AI-ready fix prompt.</p>

          <div className="mx-auto mt-9 flex max-w-2xl flex-col gap-2 rounded-2xl border border-zinc-800 bg-zinc-900/70 p-2 shadow-2xl shadow-black/20 sm:flex-row">
            <input aria-label="App URL" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scan()} placeholder="https://yourapp.com" className="min-w-0 flex-1 rounded-xl bg-transparent px-4 py-3.5 text-sm outline-none placeholder:text-zinc-600"/>
            <button onClick={scan} disabled={loading} className="inline-flex items-center justify-center gap-2 rounded-xl bg-white px-6 py-3.5 text-sm font-semibold text-black transition hover:bg-zinc-200 disabled:cursor-not-allowed disabled:opacity-50">{loading ? <><Loader2 className="animate-spin" size={17}/>Scanning</> : <>Scan app <ArrowRight size={17}/></>}</button>
          </div>
          {error && <p role="alert" className="mt-4 text-sm text-red-400">{error}</p>}
          <div className="mt-5 flex flex-wrap justify-center gap-x-5 gap-y-2 text-xs text-zinc-600"><span>HTTPS</span><span>Security headers</span><span>Mobile</span><span>Public secrets</span></div>
        </section>

        {result && <ResultView result={result}/>}
      </div>
      <footer className="mx-auto max-w-6xl border-t border-zinc-900 px-5 py-8 text-xs leading-5 text-zinc-600 sm:px-8">
        LaunchLens reports observable public signals only. It does not inspect private source code, authenticated routes, databases, or server infrastructure, and a scan cannot prove that an application is secure.
      </footer>
    </main>
  );
}

function ResultView({ result }: { result: Result }) {
  const passed = result.findings.filter((f) => f.status === "pass").length;
  const issues = result.findings.length - passed;
  const scoreTone = result.score >= 85 ? "text-emerald-400" : result.score >= 65 ? "text-amber-400" : "text-red-400";

  async function copy() {
    await navigator.clipboard.writeText(result.fixPrompt);
  }

  return (
    <section aria-label="Scan results" className="mx-auto max-w-4xl pb-20">
      <div className="grid gap-4 sm:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 sm:p-8">
          <p className="text-xs font-medium uppercase tracking-widest text-zinc-500">Observed launch score</p>
          <div className={"mt-2 text-6xl font-semibold tracking-tight " + scoreTone}>{result.score}<span className="text-2xl text-zinc-600">/100</span></div>
          <p className="mt-4 max-w-xl text-sm leading-6 text-zinc-400">{result.summary}</p>
          <div className="mt-6 border-t border-zinc-900 pt-5">
            <div className="flex items-center justify-between text-xs text-zinc-500"><span>Signal breakdown</span><span>100 starting points · {result.penaltyTotal} points deducted</span></div>
            <div className="mt-3 flex flex-wrap gap-2">
              {(["security","reliability","ux","seo"] as const).map((category) => {
                const items = result.findings.filter((f) => f.category === category);
                const warnings = items.filter((f) => f.status !== "pass").length;
                const penalty = result.categoryPenalties[category] || 0;
                return items.length ? <span key={category} className="rounded-full bg-zinc-900 px-2.5 py-1 text-[10px] uppercase tracking-wider text-zinc-500">{category === "ux" ? "UX" : category}: {warnings ? warnings + " issue" + (warnings === 1 ? "" : "s") : "clear"}{penalty ? ` · −${penalty}` : ""}</span> : null;
              })}
            </div>
          </div>
        </div>
        <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
          <p className="text-xs uppercase tracking-widest text-zinc-500">Scan target</p>
          <p className="mt-2 truncate text-sm text-zinc-300">{result.finalUrl}</p>
          <p className="mt-1 text-xs text-zinc-600">{result.redirects} redirect{result.redirects === 1 ? "" : "s"} followed · {result.durationMs} ms total</p>
          <div className="mt-5 border-t border-zinc-900 pt-5">
            <p className="text-xs uppercase tracking-widest text-zinc-500">Status</p>
            <p className="mt-2 text-xl font-semibold">{result.verdict}</p>
            <div className="mt-6 grid grid-cols-2 gap-2">
              <div className="rounded-xl bg-zinc-900 p-3"><div className="text-2xl font-semibold">{passed}</div><div className="text-xs text-zinc-500">Passed</div></div>
              <div className="rounded-xl bg-zinc-900 p-3"><div className="text-2xl font-semibold">{issues}</div><div className="text-xs text-zinc-500">Needs work</div></div>
            </div>
          </div>
        </div>
      </div>

      <details className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950 p-5 sm:p-6"><summary className="cursor-pointer list-none font-semibold">Scan details</summary><div className="mt-4 grid gap-2 text-xs sm:grid-cols-3"><div className="rounded-lg bg-zinc-900/70 p-3"><span className="text-zinc-600">Target fetch</span><div className="mt-1 text-zinc-300">{result.fetchDurationMs} ms</div></div><div className="rounded-lg bg-zinc-900/70 p-3"><span className="text-zinc-600">AI processing</span><div className="mt-1 text-zinc-300">{result.aiDurationMs} ms</div></div><div className="rounded-lg bg-zinc-900/70 p-3"><span className="text-zinc-600">Scanned</span><div className="mt-1 text-zinc-300">{new Date(result.scannedAt).toLocaleString()}</div></div></div></details>

      <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950 p-5 sm:p-6">
        <div className="flex items-center justify-between gap-4">
          <div><h2 className="font-semibold">Score calculation</h2><p className="mt-1 text-xs text-zinc-500">Transparent deductions from the 100-point starting score.</p></div>
          <span className="text-xs text-zinc-500">{result.score}/100</span>
        </div>
        <div className="mt-4 space-y-2 text-xs">
          <div className="flex justify-between rounded-lg bg-zinc-900/70 px-3 py-2"><span className="text-zinc-400">Starting points</span><span className="text-zinc-300">100</span></div>
          {result.findings.filter((f) => (f.penalty || 0) > 0).map((f, i) => <div key={i} className="flex justify-between gap-4 px-3 py-1"><span className="text-zinc-500">{f.name}</span><span className="shrink-0 text-amber-400">−{f.penalty}</span></div>)}
          <div className="mt-2 flex justify-between border-t border-zinc-900 px-3 pt-3 font-medium"><span className="text-zinc-400">Final score</span><span className={scoreTone}>{result.score}/100</span></div>
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        {(["security","reliability","ux","seo"] as const).map((category) => { const items = result.findings.filter((f) => f.category === category); if (!items.length) return null; return <div key={category} className="sm:col-span-2"><div className="mb-2 text-xs font-medium uppercase tracking-widest text-zinc-600">{category === "ux" ? "UX" : category}</div><div className="grid gap-3 sm:grid-cols-2">{items.map((f, i) => <FindingCard key={i} finding={f}/>)}</div></div>; })}
      </div>

      <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950 p-5 sm:p-6">
        <div className="flex items-center justify-between gap-4">
          <div><h2 className="font-semibold">AI fix prompt</h2><p className="mt-1 text-xs text-zinc-500">{result.aiUsed ? "AI analysis generated this prompt." : `AI unavailable (${result.aiStatus.replace("_", " ")}); deterministic fallback used.`}</p></div>
          <button onClick={copy} className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs hover:bg-zinc-900"><Copy size={14}/>Copy</button>
        </div>
        <pre className="mt-5 whitespace-pre-wrap rounded-xl bg-black/40 p-4 text-xs leading-6 text-zinc-300">{result.fixPrompt}</pre>
      </div>
    </section>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const pass = finding.status === "pass";
  return <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-5">
    <div className="flex items-start gap-3">
      {pass ? <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-400" size={19}/> : <ShieldAlert className={"mt-0.5 shrink-0 " + (finding.status === "fail" ? "text-red-400" : "text-amber-400")} size={19}/>}
      <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><h3 className="text-sm font-medium">{finding.name}</h3><span className="ml-auto text-[10px] uppercase tracking-wider text-zinc-600">{finding.status}</span></div><p className="mt-2 text-xs leading-5 text-zinc-500">{finding.detail}</p></div>
    </div>
  </div>;
}
