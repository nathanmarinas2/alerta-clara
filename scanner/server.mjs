import dns from "node:dns/promises";
import http from "node:http";

import ipaddr from "ipaddr.js";
import { chromium } from "playwright";

const port = Number(process.env.SCAN_PORT || 8090);
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 12000);
const maxRequests = Number(process.env.SCAN_MAX_REQUESTS || 100);
const scannerToken = process.env.SCANNER_TOKEN || "";
// El contenedor ejecuta como pwuser y conserva el sandbox de Chromium.
const browser = await chromium.launch({ headless: true, chromiumSandbox: true });

function publicAddress(value) {
  try {
    const range = ipaddr.parse(value).range();
    return range === "unicast";
  } catch {
    return false;
  }
}

async function validateTarget(raw) {
  const target = new URL(raw);
  if (!["http:", "https:"].includes(target.protocol)) throw new Error("scheme_not_allowed");
  if (target.username || target.password) throw new Error("credentials_not_allowed");
  if (target.port && !["80", "443"].includes(target.port)) throw new Error("port_not_allowed");
  const records = await dns.lookup(target.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((item) => !publicAddress(item.address))) {
    throw new Error("non_public_target");
  }
  return target.toString();
}

function send(response, status, payload) {
  const encoded = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": encoded.length,
    "cache-control": "no-store",
  });
  response.end(encoded);
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 32768) throw new Error("request_too_large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function scan(rawUrl) {
  const target = await validateTarget(rawUrl);
  const context = await browser.newContext({
    acceptDownloads: false,
    javaScriptEnabled: true,
    serviceWorkers: "block",
    viewport: { width: 1280, height: 720 },
  });
  const page = await context.newPage();
  context.setDefaultTimeout(timeoutMs);
  page.setDefaultNavigationTimeout(timeoutMs);
  let requestCount = 0;
  let downloadAttempted = false;
  page.on("download", () => {
    downloadAttempted = true;
  });
  await page.route("**/*", async (route) => {
    requestCount += 1;
    if (requestCount > maxRequests) return route.abort("blockedbyclient");
    if (!["GET", "HEAD"].includes(route.request().method())) {
      return route.abort("blockedbyclient");
    }
    if (["font", "image", "media", "websocket"].includes(route.request().resourceType())) {
      return route.abort("blockedbyclient");
    }
    try {
      await validateTarget(route.request().url());
      return route.continue();
    } catch {
      return route.abort("blockedbyclient");
    }
  });

  try {
    await page.goto(target, { waitUntil: "domcontentloaded", timeout: timeoutMs });
    const fields = await page.evaluate(() => ({
      password: document.querySelectorAll('input[type="password"]').length,
      payment: document.querySelectorAll(
        'input[autocomplete^="cc-"], input[name*="card" i], input[name*="tarjeta" i]'
      ).length,
      forms: Array.from(document.forms).slice(0, 20).map((form) => form.action),
    }));
    return {
      final_url: page.url(),
      password_fields: fields.password,
      payment_fields: fields.payment,
      form_actions: fields.forms,
      download_attempted: downloadAttempted,
      request_count: requestCount,
    };
  } finally {
    await context.close();
  }
}

const server = http.createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    return send(response, 200, { status: "ok" });
  }
  if (request.method !== "POST" || request.url !== "/scan") {
    return send(response, 404, { error: "not_found" });
  }
  if (scannerToken && request.headers["x-scanner-token"] !== scannerToken) {
    return send(response, 401, { error: "unauthorized" });
  }
  try {
    const body = await readBody(request);
    const result = await Promise.race([
      scan(String(body.url || "")),
      new Promise((_, reject) => setTimeout(() => reject(new Error("scan_timeout")), timeoutMs + 1000)),
    ]);
    return send(response, 200, result);
  } catch (error) {
    return send(response, 422, { error: error.message || "scan_failed" });
  }
});

server.listen(port, "0.0.0.0");

async function shutdown() {
  server.close();
  await browser.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
