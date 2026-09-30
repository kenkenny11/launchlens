import { NextResponse } from "next/server";
import dns from "node:dns/promises";
import net from "node:net";

export const runtime = "nodejs";

const MAX_HTML = 300_000;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 4;

function isPrivateIPv4(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => n < 0 || n > 255 || !Number.isInteger(n))) return true;
  return (
    parts[0] === 0 ||
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
  );
}

function ipv6ToBigInt(value: string): bigint | null {
  let ip = value.toLowerCase().split("%")[0];
  if (ip.includes(".")) {
    const lastColon = ip.lastIndexOf(":");
    const v4 = ip.slice(lastColon + 1);
    if (!/^\d+(?:\.\d+){3}$/.test(v4)) return null;
    const parts = v4.split(".").map(Number);
    if (parts.some((n) => n > 255)) return null;
    ip = ip.slice(0, lastColon + 1) +
      ((parts[0] << 8) | parts[1]).toString(16) + ":" +
      ((parts[2] << 8) | parts[3]).toString(16);
  }
  const pieces = ip.split("::");
  if (pieces.length > 2) return null;
  const left = pieces[0] ? pieces[0].split(":") : [];
  const right = pieces.length === 2 && pieces[1] ? pieces[1].split(":") : [];
  if ([...left, ...right].some((p) => !/^[0-9a-f]{1,4}$/.test(p))) return null;
  const groups = pieces.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  if (groups.length !== 8) return null;
  return groups.reduce((n, group) => (n << 16n) | BigInt(parseInt(group, 16)), 0n);
}

function isPrivateIPv6(ip: string) {
  const n = ipv6ToBigInt(ip);
  if (n === null) return true;
  const mask = (bits: number) => ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
  const prefix = (bits: number) => n & mask(bits);
  const inRange = (start: bigint, bits: number, value: bigint) => value >= start && value < start + (1n << BigInt(128 - bits));

  // Unspecified, loopback, IPv4-mapped, link-local, unique-local and multicast.
  if (n === 0n || n === 1n || prefix(7) === 0xffn) return true;
  if (prefix(10) === (0xfe80n << 118n)) return true;
  if (prefix(7) === (0xfc << 121n)) return true;
  if (prefix(96) === 0n || prefix(96) === (0xffffn << 80n)) return true;
  return false;
}

function isBlockedAddress(address: string) {
  if (net.isIP(address) === 4) return isPrivateIPv4(address);
  if (net.isIP(address) === 6) return isPrivateIPv6(address);
  return true;
}

async function assertPublicHost(url: URL) {
  const host = url.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata.google" ||
    host === "host.docker.internal"
  ) {
    throw new Error("The URL points to a blocked local or metadata host.");
  }

  if (net.isIP(host) && isBlockedAddress(host)) {
    throw new Error("The URL points to a private or reserved IP address.");
  }

  if (!net.isIP(host)) {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    if (!records.length || records.some((record) => isBlockedAddress(record.address))) {
      throw new Error("The URL resolves to a private or reserved network address.");
    }
  }
}

async function parsePublicUrl(value: string): Promise<URL | null> {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    if (url.username || url.password) return null;
    await assertPublicHost(url);
    return url;
  } catch {
    return null;
  }
}

async function fetchPublicPage(input: URL) {
  let current = input;

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
        if (!location) return response;
        current = new URL(location, checked);
        continue;
      }

      return response;
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error("Too many redirects.");
}

function addFinding(
  findings: Finding[],
  name: string,
  status: Finding["status"],
  detail: string,
  penalty = 0
) {
  findings.push({ name, status, detail });
  return penalty;
}

type Finding = {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
};

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
      max_completion_tokens: 700,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You explain observable website scan evidence. Never claim to have inspected private source code, authenticated routes, infrastructure, databases, or secrets that were not directly observed. Return valid JSON with summary and fixPrompt.",
        },
        {
          role: "user",
          content: JSON.stringify({
            score,
            findings,
            instruction:
              "Write a concise summary under 70 words. Then create a practical AI coding prompt that addresses only warnings and failures. Tell the coding agent to inspect the relevant project files itself before changing code.",
          }),
        },
      ],
    }),
  });

  if (!response.ok) throw new Error("Groq request failed");
  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) return null;

  try {
    return JSON.parse(content) as { summary: string; fixPrompt: string };
  } catch {
    return null;
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const input = typeof body?.url === "string" ? body.url.trim() : "";
    const url = await parsePublicUrl(input);

    if (!url) {
      return NextResponse.json(
        { error: "Enter a valid public http:// or https:// URL." },
        { status: 400 }
      );
    }

    const response = await fetchPublicPage(url);
    const html = (await response.text()).slice(0, MAX_HTML);
    const headers = Object.fromEntries(response.headers.entries());
    const findings: Finding[] = [];
    let score = 100;

    if (url.protocol === "https:") {
      score += addFinding(findings, "HTTPS", "pass", "The submitted URL uses HTTPS.");
    } else {
      score += addFinding(
        findings,
        "HTTPS",
        "fail",
        "The submitted URL uses plain HTTP. Use HTTPS for the production site.",
        -20
      );
    }

    const securityHeaders: Array<[string, string, number]> = [
      ["content-security-policy", "Content-Security-Policy", 8],
      ["strict-transport-security", "Strict-Transport-Security", 8],
      ["x-content-type-options", "X-Content-Type-Options", 6],
      ["referrer-policy", "Referrer-Policy", 5],
      ["permissions-policy", "Permissions-Policy", 4],
    ];

    for (const [key, label, penalty] of securityHeaders) {
      if (headers[key]) {
        findings.push({ name: label, status: "pass", detail: "Header is present." });
      } else {
        score -= penalty;
        findings.push({
          name: label,
          status: "warn",
          detail: "Header was not observed in the response.",
        });
      }
    }

    if (response.status >= 200 && response.status < 400) {
      findings.push({
        name: "HTTP response",
        status: "pass",
        detail: `The page returned HTTP ${response.status}.`,
      });
    } else {
      score -= 20;
      findings.push({
        name: "HTTP response",
        status: "fail",
        detail: `The page returned HTTP ${response.status}.`,
      });
    }

    const contentType = headers["content-type"] || "";
    if (contentType.includes("text/html")) {
      findings.push({
        name: "HTML document",
        status: "pass",
        detail: "The response declares an HTML content type.",
      });
    } else {
      score -= 8;
      findings.push({
        name: "HTML document",
        status: "warn",
        detail: `The response content type is ${contentType || "unknown"}, so page-level checks may be incomplete.`,
      });
    }

    if (/<title\b[^>]*>[\s\S]*?<\/title>/i.test(html)) {
      findings.push({ name: "Page title", status: "pass", detail: "A document title was detected." });
    } else {
      score -= 5;
      findings.push({ name: "Page title", status: "warn", detail: "No HTML title was observed." });
    }

    if (/<meta\s+[^>]*name=["']viewport["']/i.test(html)) {
      findings.push({
        name: "Mobile viewport",
        status: "pass",
        detail: "A viewport meta tag was detected.",
      });
    } else {
      score -= 5;
      findings.push({
        name: "Mobile viewport",
        status: "warn",
        detail: "No viewport meta tag was observed.",
      });
    }

    if (/<meta\s+[^>]*name=["']description["']/i.test(html)) {
      findings.push({
        name: "Meta description",
        status: "pass",
        detail: "A meta description was detected.",
      });
    } else {
      score -= 3;
      findings.push({
        name: "Meta description",
        status: "warn",
        detail: "No meta description was observed.",
      });
    }

    const secretPattern =
      /\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{20,})\b/;
    if (secretPattern.test(html)) {
      score -= 30;
      findings.push({
        name: "Possible exposed secret",
        status: "fail",
        detail:
          "A token-like pattern was detected in the fetched HTML. Treat it as potentially exposed and rotate it after checking the deployed bundle.",
      });
    } else {
      findings.push({
        name: "Public secret pattern",
        status: "pass",
        detail: "No common token pattern was detected in the fetched HTML.",
      });
    }

    score = Math.max(0, Math.min(100, score));
    const verdict =
      score >= 85 ? "LOW OBSERVED RISK" : score >= 65 ? "NEEDS ATTENTION" : "HIGH OBSERVED RISK";

    const baseFixPrompt =
      "Review my deployed application using these LaunchLens findings:\n\n" +
      findings
        .filter((f) => f.status !== "pass")
        .map((f) => `- ${f.name}: ${f.status} — ${f.detail}`)
        .join("\n") +
      "\n\nInspect the relevant project files before changing anything. Implement the safest fixes, avoid unrelated changes, and run the project's tests/build.";

    const ai = await improveWithGroq(findings, score).catch(() => null);

    return NextResponse.json({
      score,
      verdict,
      summary:
        ai?.summary ||
        "This score reflects signals observable from the public URL. It does not inspect private source code, authenticated routes, databases, or server infrastructure.",
      findings,
      fixPrompt: ai?.fixPrompt || baseFixPrompt,
    });
  } catch (error) {
    const message =
      error instanceof Error && error.name === "AbortError"
        ? "The site took too long to respond."
        : error instanceof Error
          ? error.message
          : "Could not scan that URL.";

    return NextResponse.json({ error: message }, { status: 500 });
  }
}
