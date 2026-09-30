import { NextResponse } from "next/server";
import dns from "node:dns/promises";
import net from "node:net";

export const runtime = "nodejs";

const MAX_HTML = 300_000;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 4;

async function readBodyLimit(response: Response, maxBytes: number) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = maxBytes - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      total += chunk.byteLength;
      text += decoder.decode(chunk, { stream: total < maxBytes });
      if (value.byteLength > remaining) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }

  return text + (total >= maxBytes ? decoder.decode() : "");
}

function isPrivateIPv4(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => n < 0 || n > 255 || !Number.isInteger(n))) return true;
  return (
    parts[0] === 0 || parts[0] === 10 || parts[0] === 127 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
  );
}

function isPrivateIPv6(ip: string) {
  const normalized = ip.toLowerCase().split("%")[0];
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
  if (normalized.startsWith("ff") || normalized.startsWith("::ffff:")) return true;
  return false;
}

async function assertPublicHost(url: URL) {
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" || host.endsWith(".localhost") ||
    host === "metadata.google.internal" || host === "metadata.google" ||
    host === "host.docker.internal"
  ) throw new Error("Private or metadata hosts are not allowed.");

  const ipType = net.isIP(host);
  if (ipType === 4 && isPrivateIPv4(host)) throw new Error("Private IPv4 addresses are not allowed.");
  if (ipType === 6 && isPrivateIPv6(host)) throw new Error("Private IPv6 addresses are not allowed.");

  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length) throw new Error("Could not resolve the host.");
  for (const record of records) {
    if (record.family === 4 && isPrivateIPv4(record.address)) throw new Error("The host resolves to a private IPv4 address.");
    if (record.family === 6 && isPrivateIPv6(record.address)) throw new Error("The host resolves to a private IPv6 address.");
  }
}

async function parsePublicUrl(value: string): Promise<URL | null> {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
    if (url.port && !((url.protocol === "http:" && url.port === "80") || (url.protocol === "https:" && url.port === "443"))) return null;
    await assertPublicHost(url);
    return url;
  } catch {
    return null;
  }
}

async function fetchPublicPage(input: URL) {
  let current = input;
  let redirects = 0;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const checked = await parsePublicUrl(current.toString());
    if (!checked) throw new Error("The URL or redirect target is not allowed.");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(checked, {
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "LaunchLens/0.2 (+public-url-scanner)",
          Accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        },
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) return { response, finalUrl: checked, redirects };
        current = new URL(location, checked);
        redirects++;
        continue;
      }
      return { response, finalUrl: checked, redirects };
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error("Too many redirects.");
}

type FindingCategory = "security" | "reliability" | "ux" | "seo" | "other";
type Finding = {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  category: FindingCategory;
};

function categoryFor(name: string): FindingCategory {
  if (["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "HTTPS", "Possible exposed secret", "Public secret pattern"].includes(name)) return "security";
  if (["HTTP response", "HTML document", "Redirects", "Response time"].includes(name)) return "reliability";
  if (name === "Mobile viewport") return "ux";
  if (["Page title", "Meta description"].includes(name)) return "seo";
  return "other";
}

function addFinding(findings: Finding[], name: string, status: Finding["status"], detail: string, penalty = 0) {
  findings.push({ name, status, detail, category: categoryFor(name) });
  return penalty;
}


function hasHeader(headers: Record<string, string>, name: string) {
  return typeof headers[name] === "string" && headers[name].trim().length > 0;
}

function isStrongCsp(value: string) {
  const v = value.trim().toLowerCase();
  return v.includes("default-src") || v.includes("script-src") || v.includes("object-src") || v.includes("base-uri");
}

function isValidHsts(value: string) {
  const match = value.match(/(?:^|;)\s*max-age\s*=\s*(\d+)/i);
  return Boolean(match && Number(match[1]) >= 15552000);
}

function isNoSniff(value: string) {
  return value.trim().toLowerCase() === "nosniff";
}

function isUsefulReferrerPolicy(value: string) {
  return new Set([
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin",
  ]).has(value.trim().toLowerCase());
}

async function improveWithGroq(findings: Finding[], score: number) {
  const key = process.env.GROQ_API_KEY;
  if (!key) return null;

  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: "openai/gpt-oss-120b",
      temperature: 0.2,
      max_completion_tokens: 900,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You are LaunchLens, an evidence-scoped public website scanner assistant. " +
            "Explain only what the supplied public scan observed. Never claim to have inspected private source code, " +
            "authenticated routes, infrastructure, databases, deployment configuration, or secrets that were not observed. " +
            "Security/exposure findings have highest priority, reliability second, UX/SEO third. " +
            "Missing viewport or meta description tags are not security vulnerabilities. " +
            "Return only valid JSON with exactly two string fields: summary and fixPrompt.",
        },
        {
          role: "user",
          content: JSON.stringify({
            score,
            findings,
            instruction:
              "Write a concise summary under 70 words. Then write a practical coding-agent prompt addressing only warnings and failures. " +
              "Group fixes by category and prioritize SECURITY/EXPOSURE, then RELIABILITY, then UX/SEO. " +
              "For security headers, inspect the actual framework, hosting platform, middleware, response handling, and existing policy configuration before choosing implementation or values; " +
              "never assume .htaccess, nginx, Apache, Express, or any other server type. Do not prescribe exact HSTS max-age, includeSubDomains, CSP directives, nonces, hashes, or Permissions-Policy feature allowances unless the target project's architecture and required resources justify them. " +
              "Avoid blindly copying example header policies: preserve required application functionality and use the least-permissive compatible policy. Treat viewport as UX and meta description as SEO. " +
              "Tell the coding agent to inspect relevant files first, identify required scripts/styles/assets and deployment behavior, make minimal safe changes, verify headers and page metadata, and run tests/build before deployment.",
          }),
        },
      ],
    }),
  });

  if (!response.ok) return null;

  const data = await response.json().catch(() => null);
  const raw = data?.choices?.[0]?.message?.content;
  if (typeof raw !== "string" || !raw.trim()) return null;

  try {
    const cleaned = raw.trim().replace(/^\`\`\`(?:json)?\s*/i, "").replace(/\s*\`\`\`$/i, "").trim();
    const parsed = JSON.parse(cleaned);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof parsed.summary !== "string" ||
      typeof parsed.fixPrompt !== "string" ||
      !parsed.summary.trim() ||
      !parsed.fixPrompt.trim()
    ) return null;
    return {
      summary: parsed.summary.trim().slice(0, 600),
      fixPrompt: parsed.fixPrompt.trim().slice(0, 5000),
    };
  } catch {
    return null;
  }
}

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 10;
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function getClientKey(req: Request) {
  const forwarded = req.headers.get("x-forwarded-for");
  return (forwarded?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown").slice(0, 100);
}

function checkRateLimit(key: string) {
  const now = Date.now();
  const current = rateLimitStore.get(key);

  if (!current || current.resetAt <= now) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, retryAfter: 60 };
  }

  current.count += 1;
  if (current.count > RATE_LIMIT_MAX_REQUESTS) {
    return { allowed: false, retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
  }

  return { allowed: true, retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
}

export async function POST(req: Request) {
  try {
    const limit = checkRateLimit(getClientKey(req));
    if (!limit.allowed) {
      return NextResponse.json(
        { error: "Too many scans. Please wait before trying again." },
        { status: 429, headers: { "Retry-After": String(limit.retryAfter) } }
      );
    }

    const body = await req.json();
    const input = typeof body?.url === "string" ? body.url.trim() : "";
    const url = await parsePublicUrl(input);
    if (!url) return NextResponse.json({ error: "Enter a valid public http:// or https:// URL." }, { status: 400 });

    const startedAt = Date.now();
    const fetched = await fetchPublicPage(url);
    const response = fetched.response;
    const finalUrl = fetched.finalUrl;
    const redirects = fetched.redirects;
    const html = await readBodyLimit(response, MAX_HTML);
    const headers = Object.fromEntries(response.headers.entries());
    const findings: Finding[] = [];
    let score = 100;

    if (finalUrl.protocol === "https:") {
      score += addFinding(findings, "HTTPS", "pass", "The submitted URL uses HTTPS.");
    } else {
      score += addFinding(findings, "HTTPS", "fail", "The submitted URL uses plain HTTP. Use HTTPS for the production site.", -20);
    }

    const csp = headers["content-security-policy"];
    if (!hasHeader(headers, "content-security-policy")) {
      score -= 8;
      findings.push({ name: "Content-Security-Policy", status: "warn", detail: "Header was not observed in the final response.", category: "security" });
    } else if (!isStrongCsp(csp)) {
      score -= 3;
      findings.push({ name: "Content-Security-Policy", status: "warn", detail: "A CSP header is present, but common source directives were not observed.", category: "security" });
    } else {
      findings.push({ name: "Content-Security-Policy", status: "pass", detail: "A CSP header with common source directives is present.", category: "security" });
    }

    const hsts = headers["strict-transport-security"];
    if (finalUrl.protocol === "https:") {
      if (!hasHeader(headers, "strict-transport-security")) {
        score -= 8;
        findings.push({ name: "Strict-Transport-Security", status: "warn", detail: "Header was not observed in the final HTTPS response.", category: "security" });
      } else if (!isValidHsts(hsts)) {
        score -= 3;
        findings.push({ name: "Strict-Transport-Security", status: "warn", detail: "HSTS is present, but max-age is missing or shorter than 180 days.", category: "security" });
      } else {
        findings.push({ name: "Strict-Transport-Security", status: "pass", detail: "HSTS is present with max-age of at least 180 days.", category: "security" });
      }
    } else {
      findings.push({ name: "Strict-Transport-Security", status: "pass", detail: "HSTS was not evaluated because the final response uses HTTP.", category: "security" });
    }

    const xcto = headers["x-content-type-options"];
    if (!hasHeader(headers, "x-content-type-options")) {
      score -= 6;
      findings.push({ name: "X-Content-Type-Options", status: "warn", detail: "Header was not observed in the final response.", category: "security" });
    } else if (!isNoSniff(xcto)) {
      score -= 2;
      findings.push({ name: "X-Content-Type-Options", status: "warn", detail: "Header is present but is not set to nosniff.", category: "security" });
    } else {
      findings.push({ name: "X-Content-Type-Options", status: "pass", detail: "Header is set to nosniff.", category: "security" });
    }

    const referrer = headers["referrer-policy"];
    if (!hasHeader(headers, "referrer-policy")) {
      score -= 5;
      findings.push({ name: "Referrer-Policy", status: "warn", detail: "Header was not observed in the final response.", category: "security" });
    } else if (!isUsefulReferrerPolicy(referrer)) {
      score -= 2;
      findings.push({ name: "Referrer-Policy", status: "warn", detail: "Header is present but uses an unrecognized policy value.", category: "security" });
    } else {
      findings.push({ name: "Referrer-Policy", status: "pass", detail: `Header uses ${referrer.trim()}.`, category: "security" });
    }

    const permissions = headers["permissions-policy"];
    if (!hasHeader(headers, "permissions-policy")) {
      score -= 4;
      findings.push({ name: "Permissions-Policy", status: "warn", detail: "Header was not observed in the final response.", category: "security" });
    } else {
      findings.push({ name: "Permissions-Policy", status: "pass", detail: "A Permissions-Policy header is present.", category: "security" });
    }

    if (response.status >= 200 && response.status < 400) {
      findings.push({ name: "HTTP response", status: "pass", detail: `The page returned HTTP ${response.status}.`, category: "reliability" });
    } else {
      score -= 20;
      findings.push({ name: "HTTP response", status: "fail", detail: `The page returned HTTP ${response.status}.`, category: "reliability" });
    }

    if (redirects > 0) {
      findings.push({ name: "Redirects", status: "pass", detail: `The public URL completed ${redirects} redirect${redirects === 1 ? "" : "s"} before the final response.`, category: "reliability" });
    }

    const elapsedMs = Date.now() - startedAt;
    if (elapsedMs <= 3000) {
      findings.push({ name: "Response time", status: "pass", detail: `The scan completed in about ${elapsedMs} ms.`, category: "reliability" });
    } else if (elapsedMs <= 7000) {
      score -= 2;
      findings.push({ name: "Response time", status: "warn", detail: `The scan took about ${elapsedMs} ms. Slower responses may affect user experience.`, category: "reliability" });
    } else {
      score -= 5;
      findings.push({ name: "Response time", status: "warn", detail: `The scan took about ${elapsedMs} ms. This is a high-latency signal for a public page.`, category: "reliability" });
    }

    const contentType = headers["content-type"] || "";
    if (contentType.includes("text/html")) {
      findings.push({ name: "HTML document", status: "pass", detail: "The response declares an HTML content type.", category: "reliability" });
    } else {
      score -= 8;
      findings.push({ name: "HTML document", status: "warn", detail: `The response content type is ${contentType || "unknown"}, so page-level checks may be incomplete.`, category: "reliability" });
    }

    if (/<title\b[^>]*>[\s\S]*?<\/title>/i.test(html)) {
      findings.push({ name: "Page title", status: "pass", detail: "A document title was detected.", category: "seo" });
    } else {
      score -= 5;
      findings.push({ name: "Page title", status: "warn", detail: "No HTML title was observed.", category: "seo" });
    }

    if (/<meta\s+[^>]*name=["']viewport["']/i.test(html)) {
      findings.push({ name: "Mobile viewport", status: "pass", detail: "A viewport meta tag was detected.", category: "ux" });
    } else {
      score -= 2;
      findings.push({ name: "Mobile viewport", status: "warn", detail: "No viewport meta tag was observed. Mobile rendering may still work, but this is a compatibility signal.", category: "ux" });
    }

    if (/<meta\s+[^>]*name=["']description["']/i.test(html)) {
      findings.push({ name: "Meta description", status: "pass", detail: "A meta description was detected.", category: "seo" });
    } else {
      score -= 1;
      findings.push({ name: "Meta description", status: "warn", detail: "No meta description was observed. This is primarily an SEO/share-preview signal, not proof of a security issue.", category: "seo" });
    }

    const secretPattern = /\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{20,})\b/;
    if (secretPattern.test(html)) {
      score -= 30;
      findings.push({ name: "Possible exposed secret", status: "fail", detail: "A token-like pattern was detected in the fetched HTML. Treat it as potentially exposed and rotate it after checking the deployed bundle.", category: "security" });
    } else {
      findings.push({ name: "Public secret pattern", status: "pass", detail: "No common token pattern was detected in the fetched HTML.", category: "security" });
    }

    score = Math.max(0, Math.min(100, score));

    const verdict =
      score >= 85
        ? "LOW WEB SIGNAL RISK"
        : score >= 65
          ? "SOME HARDENING NEEDED"
          : "MORE REVIEW NEEDED";

    const baseFixPrompt =
      "Review my deployed application using these LaunchLens findings. Prioritize security and reliability before UX or SEO improvements.\n\n" +
      findings
        .filter((f) => f.status !== "pass")
        .map((f) => `- [${f.category.toUpperCase()}] ${f.name}: ${f.status} — ${f.detail}`)
        .join("\n") +
      "\n\nInspect the relevant project files before changing anything. Implement the safest fixes, avoid unrelated changes, and run the project's tests/build.";

    const ai = await improveWithGroq(findings, score).catch(() => null);

    return NextResponse.json({
      score,
      verdict,
      finalUrl: finalUrl.toString(),
      redirects,
      summary:
        ai?.summary ||
        "This score reflects signals observable from the public URL. It is not a complete security audit and does not inspect private source code, authenticated routes, databases, or server infrastructure.",
      findings,
      fixPrompt: ai?.fixPrompt || baseFixPrompt,
      aiUsed: Boolean(ai),
    });
  } catch (error) {
    const message =
      error instanceof Error && error.name === "AbortError"
        ? "The site took too long to respond."
        : error instanceof Error
          ? error.message
          : "Could not scan that URL.";
    const status = /too many scans/i.test(message) ? 429 : 500;
    return NextResponse.json({ error: message }, { status });
  }
}