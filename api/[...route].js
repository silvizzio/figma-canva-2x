/**
 * figma-canva-2x relay on Vercel.
 *
 * One catch-all function serves every route:
 *   GET  /api/connect?key=...      Starts the Canva OAuth flow (open once in a browser)
 *   GET  /api/oauth-callback       Canva redirects here, tokens are stored in Redis
 *   GET  /api/status               Reports connection state (header x-plugin-key)
 *   GET  /api/disconnect?key=...   Deletes the stored tokens
 *   POST /api/upload-frame         { fileKey, nodeId, name } renders at 2x and sends the URL to Canva
 *   POST /api/upload-bytes         { name, dataBase64 } fallback for small PNGs
 *   GET  /api/job?id=...&kind=url  Polls a Canva upload job
 *
 * The primary path never carries the image through this function. Figma renders the
 * node at scale 2, and Canva fetches that render URL directly, so the Vercel 4.5 MB
 * body limit never applies.
 *
 * Environment variables:
 *   CANVA_CLIENT_ID, CANVA_CLIENT_SECRET, PLUGIN_KEY, FIGMA_TOKEN, RELAY_ORIGIN
 *   KV_REST_API_URL, KV_REST_API_TOKEN  (Upstash, added through the Vercel marketplace)
 */

import crypto from "node:crypto";

export const config = { maxDuration: 30 };

const CANVA_AUTH_URL = "https://www.canva.com/api/oauth/authorize";
const CANVA_TOKEN_URL = "https://api.canva.com/rest/v1/oauth/token";
const CANVA_API = "https://api.canva.com/rest/v1";
const FIGMA_API = "https://api.figma.com/v1";
const SCOPES = "asset:read asset:write";

const TOKEN_KEY = "canva:token";
const PKCE_PREFIX = "canva:pkce:";
const PKCE_TTL_SECONDS = 600;

const MAX_NAME_LENGTH = 50; // Canva limit for an asset name.
const MAX_BYTES_FALLBACK = 3000000; // Keep the base64 body under the Vercel 4.5 MB cap.
const INLINE_POLL_ATTEMPTS = 6;
const POLL_INTERVAL_MS = 1200;

export default async function handler(request, response) {
  setCors(response);

  if (request.method === "OPTIONS") {
    response.status(204).end();
    return;
  }

  const route = Array.isArray(request.query.route)
    ? request.query.route.join("/")
    : String(request.query.route || "");

  try {
    switch (route) {
      case "connect":
        return await handleConnect(request, response);
      case "oauth-callback":
        return await handleCallback(request, response);
      case "status":
        return await handleStatus(request, response);
      case "disconnect":
        return await handleDisconnect(request, response);
      case "upload-frame":
        return await handleUploadFrame(request, response);
      case "upload-bytes":
        return await handleUploadBytes(request, response);
      case "job":
        return await handleJob(request, response);
      default:
        return response.status(404).json({ error: `Unknown route: ${route}` });
    }
  } catch (error) {
    const status = error && error.status ? error.status : 500;
    const code = error && error.code ? error.code : "relay_error";
    const message = error && error.message ? error.message : String(error);
    return response.status(status).json({ error: message, code });
  }
}

/* ----------------------------------------------------------------------------
 * OAuth
 * ------------------------------------------------------------------------- */

async function handleConnect(request, response) {
  requireKey(request.query.key);

  const codeVerifier = base64Url(crypto.randomBytes(96));
  const codeChallenge = base64Url(crypto.createHash("sha256").update(codeVerifier).digest());
  const state = base64Url(crypto.randomBytes(48));
  const redirectUri = `${originOf(request)}/api/oauth-callback`;

  await redis(["SET", PKCE_PREFIX + state, JSON.stringify({ codeVerifier, redirectUri }), "EX", String(PKCE_TTL_SECONDS)]);

  const url = new URL(CANVA_AUTH_URL);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", requireEnv("CANVA_CLIENT_ID"));
  url.searchParams.set("state", state);
  url.searchParams.set("redirect_uri", redirectUri);

  response.redirect(302, url.toString());
}

async function handleCallback(request, response) {
  const { code, state, error } = request.query;

  if (error) return sendHtml(response, 400, `<h1>Canva returned an error</h1><p>${escapeHtml(String(error))}</p>`);
  if (!code || !state) return sendHtml(response, 400, "<h1>Missing code or state</h1>");

  const stored = await redis(["GET", PKCE_PREFIX + state]);
  if (!stored) {
    return sendHtml(response, 400, "<h1>State is unknown or expired</h1><p>Open /api/connect again.</p>");
  }
  await redis(["DEL", PKCE_PREFIX + state]);

  const { codeVerifier, redirectUri } = JSON.parse(stored);

  const token = await requestToken({
    grant_type: "authorization_code",
    code_verifier: codeVerifier,
    code: String(code),
    redirect_uri: redirectUri,
  });
  await saveToken(token);

  return sendHtml(response, 200, "<h1>Canva is connected</h1><p>You can close this tab and go back to Figma.</p>");
}

async function handleStatus(request, response) {
  requireKey(request.headers["x-plugin-key"] || request.query.key);

  const record = await readToken();
  if (!record) return response.status(200).json({ connected: false });

  return response.status(200).json({
    connected: true,
    expiresAt: record.expiresAt,
    expiresInSeconds: Math.max(0, Math.round((record.expiresAt - Date.now()) / 1000)),
    figmaTokenSet: Boolean(process.env.FIGMA_TOKEN),
  });
}

async function handleDisconnect(request, response) {
  requireKey(request.query.key);
  await redis(["DEL", TOKEN_KEY]);
  return response.status(200).json({ disconnected: true });
}

async function requestToken(fields) {
  const credentials = Buffer.from(
    `${requireEnv("CANVA_CLIENT_ID")}:${requireEnv("CANVA_CLIENT_SECRET")}`
  ).toString("base64");

  const result = await fetch(CANVA_TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(fields).toString(),
  });

  const data = await result.json().catch(() => ({}));
  if (!result.ok) {
    throw fail(`Canva token request failed: ${data.code || result.status} ${data.message || ""}`, 502, "canva_token_failed");
  }
  return data;
}

async function saveToken(token) {
  const record = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    expiresAt: Date.now() + token.expires_in * 1000,
  };
  await redis(["SET", TOKEN_KEY, JSON.stringify(record)]);
  return record;
}

async function readToken() {
  const raw = await redis(["GET", TOKEN_KEY]);
  return raw ? JSON.parse(raw) : null;
}

async function accessToken(forceRefresh) {
  const record = await readToken();
  if (!record) {
    throw fail("The relay is not connected to Canva. Open /api/connect?key=... in a browser.", 409, "not_connected");
  }

  if (!forceRefresh && Date.now() < record.expiresAt - 120000) {
    return record.accessToken;
  }

  // Each Canva refresh token works once, so the new pair replaces the old one.
  const token = await requestToken({ grant_type: "refresh_token", refresh_token: record.refreshToken });
  const updated = await saveToken(token);
  return updated.accessToken;
}

/* ----------------------------------------------------------------------------
 * Upload from a Figma render URL (primary path)
 * ------------------------------------------------------------------------- */

async function handleUploadFrame(request, response) {
  requirePost(request);
  requireKey(request.headers["x-plugin-key"]);

  const body = readJsonBody(request);
  const fileKey = String(body.fileKey || "").trim();
  const nodeId = String(body.nodeId || "").trim();
  const name = trimName(body.name);

  if (!fileKey || !nodeId) {
    throw fail("fileKey and nodeId are required.", 400, "bad_request");
  }

  const imageUrl = await renderAtTwoX(fileKey, nodeId);

  let token = await accessToken(false);
  let job = await createUrlUploadJob(token, name, imageUrl);

  if (job.unauthorized) {
    token = await accessToken(true);
    job = await createUrlUploadJob(token, name, imageUrl);
  }

  const finished = await pollInline(token, job.id, "url", job.raw);
  return response.status(200).json(finished);
}

async function renderAtTwoX(fileKey, nodeId) {
  const figmaToken = requireEnv("FIGMA_TOKEN");
  const url = `${FIGMA_API}/images/${encodeURIComponent(fileKey)}?ids=${encodeURIComponent(nodeId)}&format=png&scale=2`;

  const result = await fetch(url, { headers: { "X-Figma-Token": figmaToken } });
  const data = await result.json().catch(() => ({}));

  if (!result.ok) {
    throw fail(`Figma render failed (${result.status}): ${data.err || data.message || "unknown"}`, 502, "figma_render_failed");
  }
  if (data.err) {
    throw fail(`Figma render failed: ${data.err}`, 502, "figma_render_failed");
  }

  const imageUrl = data.images && data.images[nodeId];
  if (!imageUrl) {
    throw fail("Figma returned no image for this node.", 502, "figma_render_failed");
  }
  return imageUrl;
}

async function createUrlUploadJob(token, name, imageUrl) {
  const result = await fetch(`${CANVA_API}/url-asset-uploads`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name, url: imageUrl }),
  });

  if (result.status === 401) return { unauthorized: true };

  const data = await result.json().catch(() => ({}));

  if (result.status === 429) {
    throw fail("Canva rate limit reached.", 429, "rate_limited");
  }
  if (!result.ok) {
    throw fail(data.message || `Canva rejected the upload (${result.status}).`, 502, data.code || "canva_upload_failed");
  }
  return { id: data.job && data.job.id, raw: data.job };
}

/* ----------------------------------------------------------------------------
 * Upload raw bytes (fallback for small files)
 * ------------------------------------------------------------------------- */

async function handleUploadBytes(request, response) {
  requirePost(request);
  requireKey(request.headers["x-plugin-key"]);

  const body = readJsonBody(request);
  const name = trimName(body.name);
  const dataBase64 = String(body.dataBase64 || "");

  if (!dataBase64) throw fail("dataBase64 is required.", 400, "bad_request");

  const bytes = Buffer.from(dataBase64, "base64");
  if (bytes.length > MAX_BYTES_FALLBACK) {
    throw fail(
      `This PNG is ${(bytes.length / 1048576).toFixed(1)} MB. Vercel caps a function body at 4.5 MB, so use the Figma render path instead.`,
      413,
      "payload_too_large"
    );
  }

  let token = await accessToken(false);
  let job = await createByteUploadJob(token, name, bytes);

  if (job.unauthorized) {
    token = await accessToken(true);
    job = await createByteUploadJob(token, name, bytes);
  }

  const finished = await pollInline(token, job.id, "bytes", job.raw);
  return response.status(200).json(finished);
}

async function createByteUploadJob(token, name, bytes) {
  const result = await fetch(`${CANVA_API}/asset-uploads`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/octet-stream",
      "Asset-Upload-Metadata": JSON.stringify({ name_base64: Buffer.from(name, "utf8").toString("base64") }),
    },
    body: bytes,
  });

  if (result.status === 401) return { unauthorized: true };

  const data = await result.json().catch(() => ({}));

  if (result.status === 429) {
    throw fail("Canva rate limit reached.", 429, "rate_limited");
  }
  if (!result.ok) {
    throw fail(data.message || `Canva rejected the upload (${result.status}).`, 502, data.code || "canva_upload_failed");
  }
  return { id: data.job && data.job.id, raw: data.job };
}

/* ----------------------------------------------------------------------------
 * Job polling
 * ------------------------------------------------------------------------- */

async function handleJob(request, response) {
  requireKey(request.headers["x-plugin-key"] || request.query.key);

  const id = String(request.query.id || "");
  const kind = request.query.kind === "bytes" ? "bytes" : "url";
  if (!id) throw fail("id is required.", 400, "bad_request");

  const token = await accessToken(false);
  const job = await readJob(token, id, kind);
  return response.status(200).json(describeJob(job));
}

async function readJob(token, id, kind) {
  const path = kind === "bytes" ? "asset-uploads" : "url-asset-uploads";
  const result = await fetch(`${CANVA_API}/${path}/${id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await result.json().catch(() => ({}));

  if (!result.ok) {
    throw fail(data.message || `Job read failed (${result.status}).`, 502, "job_read_failed");
  }
  return data.job || {};
}

/**
 * Waits a short time inside the request, so most frames finish in one round trip.
 * Anything slower is handed back to the plugin, which polls /api/job.
 */
async function pollInline(token, jobId, kind, initialJob) {
  let job = initialJob || {};

  for (let attempt = 0; attempt < INLINE_POLL_ATTEMPTS; attempt += 1) {
    if (job.status && job.status !== "in_progress") {
      return describeJob(job, jobId, kind);
    }
    await sleep(POLL_INTERVAL_MS);
    job = await readJob(token, jobId, kind);
  }

  return describeJob(job, jobId, kind);
}

function describeJob(job, jobId, kind) {
  const asset = job.asset || {};
  const metadata = asset.metadata || {};

  return {
    status: job.status || "in_progress",
    jobId: job.id || jobId,
    kind: kind || "url",
    assetId: asset.id || null,
    name: asset.name || null,
    width: metadata.width || null,
    height: metadata.height || null,
    error: job.error || null,
  };
}

/* ----------------------------------------------------------------------------
 * Storage (Upstash Redis over REST)
 * ------------------------------------------------------------------------- */

async function redis(command) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    throw fail("Redis environment variables are missing. Add the Upstash integration.", 500, "no_store");
  }

  const result = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(command),
  });

  const data = await result.json().catch(() => ({}));
  if (data.error) throw fail(`Redis error: ${data.error}`, 500, "store_error");
  return data.result;
}

/* ----------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw fail(`${name} is not set on the project.`, 500, "missing_env");
  return value;
}

function requireKey(value) {
  const expected = requireEnv("PLUGIN_KEY");
  if (value !== expected) throw fail("Invalid or missing plugin key.", 401, "unauthorized");
}

function requirePost(request) {
  if (request.method !== "POST") throw fail("Use POST.", 405, "method_not_allowed");
}

function readJsonBody(request) {
  const body = request.body;
  if (!body) return {};
  if (typeof body === "string") {
    try {
      return JSON.parse(body);
    } catch (error) {
      throw fail("The body is not valid JSON.", 400, "bad_request");
    }
  }
  return body;
}

function trimName(value) {
  const clean = String(value || "Untitled").replace(/\s+/g, " ").trim() || "Untitled";
  return clean.length > MAX_NAME_LENGTH ? clean.slice(0, MAX_NAME_LENGTH).trim() : clean;
}

function originOf(request) {
  if (process.env.RELAY_ORIGIN) return process.env.RELAY_ORIGIN.replace(/\/+$/, "");
  const proto = request.headers["x-forwarded-proto"] || "https";
  return `${proto}://${request.headers.host}`;
}

function base64Url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fail(message, status, code) {
  const error = new Error(message);
  error.status = status || 500;
  error.code = code || "relay_error";
  return error;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setCors(response) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "content-type, x-plugin-key");
  response.setHeader("Access-Control-Max-Age", "86400");
}

function sendHtml(response, status, body) {
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  response.status(status).send(
    `<!doctype html><meta charset="utf-8"><title>figma-canva-2x</title>
<style>body{font:16px/1.5 -apple-system,system-ui,sans-serif;margin:48px auto;max-width:40rem;color:#1b1b1b}h1{font-size:1.25rem}</style>
${body}`
  );
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character];
  });
}
