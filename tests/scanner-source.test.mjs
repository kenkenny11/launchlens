import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../app/api/scan/route.ts", import.meta.url), "utf8");

test("SSRF protections remain present", () => {
  assert.match(source, /localhost/);
  assert.match(source, /metadata\.google/);
  assert.match(source, /dns\.lookup/);
  assert.match(source, /isPrivateIPv4/);
  assert.match(source, /isPrivateIPv6/);
});

test("redirects are manually followed and bounded", () => {
  assert.match(source, /redirect:\s*"manual"/);
  assert.match(source, /MAX_REDIRECTS/);
});

test("response body and request time limits remain present", () => {
  assert.match(source, /MAX_HTML/);
  assert.match(source, /REQUEST_TIMEOUT_MS/);
  assert.match(source, /readBodyLimit/);
});

test("AI analysis has a bounded timeout and deterministic fallback", () => {
  assert.match(source, /AI_TIMEOUT_MS/);
  assert.match(source, /AbortController/);
  assert.match(source, /aiStatus/);
  assert.match(source, /baseFixPrompt/);
});

test("security and metadata checks remain present", () => {
  assert.match(source, /Content-Security-Policy/);
  assert.match(source, /Strict-Transport-Security/);
  assert.match(source, /X-Content-Type-Options/);
  assert.match(source, /Referrer-Policy/);
  assert.match(source, /Permissions-Policy/);
  assert.match(source, /Mobile viewport/);
  assert.match(source, /Meta description/);
});

test("score deductions remain transparent", () => {
  assert.match(source, /penaltyTotal/);
  assert.match(source, /categoryPenalties/);
  assert.match(source, /penalty\?: number/);
});


test("production response headers are configured outside HTML metadata", async () => {
  const nextConfig = await readFile(new URL("../next.config.ts", import.meta.url), "utf8");
  assert.match(nextConfig, /Content-Security-Policy/);
  assert.match(nextConfig, /X-Content-Type-Options/);
  assert.match(nextConfig, /Referrer-Policy/);
  assert.match(nextConfig, /Permissions-Policy/);
  assert.match(nextConfig, /source: "\/(.*)"/);
});
