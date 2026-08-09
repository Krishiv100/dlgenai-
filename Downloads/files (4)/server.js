'use strict';
/**
 * LLM Action Firewall — deterministic post-generation, pre-execution check.
 *
 * No LLM, no heuristics, no suspicious-phrase matching. The boundary is:
 * top-level schema -> tool allowlist -> per-tool arg schema -> tenant scope
 * -> exact egress domain -> human approval -> structural HTML safety.
 *
 * The first failing check wins. Untrusted provenance / injected instructions
 * in `untrustedContent` are never inspected for intent: a read-only action
 * that satisfies its schema is allowed regardless of what the model read.
 */

const http = require('http');

// ---------------------------------------------------------------- scope ----
const TENANT_ID = process.env.TENANT_ID || 'tenant-yvw0kq2';
const EMAIL_DOMAIN = (process.env.EMAIL_DOMAIN || 'notify-1jeevep.example').toLowerCase();
const PORT = Number(process.env.PORT) || 8080;
const MAX_BODY_BYTES = 1024 * 1024;

const REASON = {
  ALLOW: 'ALLOW',
  INVALID_SCHEMA: 'INVALID_SCHEMA',
  TOOL_NOT_ALLOWED: 'TOOL_NOT_ALLOWED',
  TENANT_SCOPE: 'TENANT_SCOPE',
  EGRESS_DENIED: 'EGRESS_DENIED',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  UNSAFE_OUTPUT: 'UNSAFE_OUTPUT',
};

const allow = () => ({ decision: 'allow', reason: REASON.ALLOW });
const block = (reason) => ({ decision: 'block', reason });

// ------------------------------------------------------------- helpers ----
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isString = (v) => typeof v === 'string';
const charLen = (s) => Array.from(s).length; // count code points, not UTF-16 units

/** Exact key-set equality: no missing keys, no extra keys. */
function keysExactly(obj, expected) {
  const keys = Object.keys(obj);
  if (keys.length !== expected.length) return false;
  const want = new Set(expected);
  return keys.every((k) => want.has(k));
}

// -------------------------------------------------- tool argument schemas --
// Declarative table. A tool that is not a key here is not callable at all.
const TOOL_SCHEMAS = {
  search: {
    keys: ['query'],
    valid: (a) => isString(a.query) && charLen(a.query) >= 1 && charLen(a.query) <= 200,
  },
  lookup_record: {
    keys: ['tenantId', 'recordId'],
    valid: (a) =>
      isString(a.tenantId) && a.tenantId.length > 0 &&
      isString(a.recordId) && a.recordId.length > 0,
  },
  send_email: {
    keys: ['to', 'subject', 'body'],
    valid: (a) =>
      isString(a.to) && a.to.length > 0 && isString(a.subject) && isString(a.body),
  },
  render_html: {
    keys: ['html'],
    valid: (a) => isString(a.html),
  },
};

// ------------------------------------------------------ egress: recipient --
/**
 * Returns the lowercased recipient domain, or null if the address is not a
 * single deliverable mailbox. Header-injection characters and multi-recipient
 * strings return null so they fail the exact-match test.
 */
function recipientDomain(to) {
  if (/[\s,;<>"()\[\]\\]/.test(to)) return null;         // one plain mailbox only
  const at = to.indexOf('@');
  if (at <= 0) return null;                              // no local part / no @
  if (to.indexOf('@', at + 1) !== -1) return null;       // more than one @
  const domain = to.slice(at + 1);
  if (!domain || domain.startsWith('.') || domain.endsWith('.')) return null;
  return domain.toLowerCase();
}

// -------------------------------------------------- structural HTML check --
const BLOCKED_TAGS = new Set([
  'script', 'iframe', 'object', 'embed', 'frame', 'frameset', 'applet', 'base',
]);
const BLOCKED_SCHEMES = ['javascript:', 'vbscript:', 'data:text/html'];

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", colon: ':', tab: '\t',
  newline: '\n', sol: '/', nbsp: '\u00a0', semi: ';', lpar: '(', rpar: ')',
};

/** Decode numeric and a small set of named entities so `&#106;avascript:` is caught. */
function decodeEntities(s) {
  return s.replace(/&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);?/g, (m, g) => {
    if (g[0] === '#') {
      const hex = g[1] === 'x' || g[1] === 'X';
      const code = parseInt(hex ? g.slice(2) : g.slice(1), hex ? 16 : 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return m;
      try { return String.fromCodePoint(code); } catch { return m; }
    }
    const key = g.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, key)
      ? NAMED_ENTITIES[key]
      : m;
  });
}

/** Scheme check after entity decoding and removal of control/space characters. */
function isDangerousUrlValue(value) {
  const s = decodeEntities(value)
    .replace(/[\u0000-\u0020\u007f]/g, '')
    .toLowerCase();
  return BLOCKED_SCHEMES.some((scheme) => s.startsWith(scheme));
}

/**
 * Minimal HTML tokenizer. Walks tags and attributes structurally rather than
 * pattern-matching on strings, so quoting, casing and entity tricks can't slip
 * an executable construct past the check. Returns true when the markup is safe.
 */
function htmlIsSafe(html) {
  const n = html.length;
  let i = 0;

  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt === -1) break;

    if (html.startsWith('<!--', lt)) {                   // comment
      const end = html.indexOf('-->', lt + 4);
      i = end === -1 ? n : end + 3;
      continue;
    }
    if (html.startsWith('<!', lt) || html.startsWith('<?', lt)) {  // doctype / PI
      const end = html.indexOf('>', lt);
      i = end === -1 ? n : end + 1;
      continue;
    }

    let j = lt + 1;
    const closing = html[j] === '/';
    if (closing) j++;

    const nameStart = j;
    while (j < n && /[A-Za-z0-9:_-]/.test(html[j])) j++;
    const tagName = html.slice(nameStart, j).toLowerCase();

    if (!tagName) { i = lt + 1; continue; }              // stray '<' in text
    if (BLOCKED_TAGS.has(tagName)) return false;
    if (closing) {
      const end = html.indexOf('>', j);
      i = end === -1 ? n : end + 1;
      continue;
    }

    // attributes
    while (j < n) {
      while (j < n && /\s/.test(html[j])) j++;
      if (j >= n) break;
      if (html[j] === '>') { j++; break; }
      if (html[j] === '/') { j++; continue; }

      const attrStart = j;
      while (j < n && !/[\s=>/]/.test(html[j])) j++;
      const attrName = html.slice(attrStart, j).toLowerCase();
      if (!attrName) { j++; continue; }

      let value = '';
      let k = j;
      while (k < n && /\s/.test(html[k])) k++;
      if (html[k] === '=') {
        k++;
        while (k < n && /\s/.test(html[k])) k++;
        const quote = html[k];
        if (quote === '"' || quote === "'") {
          const end = html.indexOf(quote, k + 1);
          value = end === -1 ? html.slice(k + 1) : html.slice(k + 1, end);
          k = end === -1 ? n : end + 1;
        } else {
          const vs = k;
          while (k < n && !/[\s>]/.test(html[k])) k++;
          value = html.slice(vs, k);
        }
        j = k;
      }

      if (/^on/.test(attrName)) return false;            // inline event handler
      if (value && isDangerousUrlValue(value)) return false;
    }
    i = j;
  }
  return true;
}

// -------------------------------------------------------------- decision ---
function evaluate(body) {
  // 1. top-level request schema
  if (!isObject(body)) return block(REASON.INVALID_SCHEMA);

  const { provenance, humanApproved, untrustedContent, action } = body;

  if (provenance !== 'trusted' && provenance !== 'untrusted') {
    return block(REASON.INVALID_SCHEMA);
  }
  if (humanApproved !== undefined && typeof humanApproved !== 'boolean') {
    return block(REASON.INVALID_SCHEMA);
  }
  if (untrustedContent !== undefined && untrustedContent !== null && !isString(untrustedContent)) {
    return block(REASON.INVALID_SCHEMA);
  }
  if (!isObject(action) || !isString(action.tool) || action.tool.length === 0) {
    return block(REASON.INVALID_SCHEMA);
  }
  if (!isObject(action.args)) return block(REASON.INVALID_SCHEMA);

  const { tool, args } = action;
  const approved = humanApproved === true;

  // 2. tool allowlist
  const schema = Object.prototype.hasOwnProperty.call(TOOL_SCHEMAS, tool)
    ? TOOL_SCHEMAS[tool]
    : null;
  if (!schema) return block(REASON.TOOL_NOT_ALLOWED);

  // 3. selected tool's argument schema (exact keys, correct types/bounds)
  if (!keysExactly(args, schema.keys) || !schema.valid(args)) {
    return block(REASON.INVALID_SCHEMA);
  }

  // 4. tenant scope
  if (tool === 'lookup_record' && args.tenantId !== TENANT_ID) {
    return block(REASON.TENANT_SCOPE);
  }

  if (tool === 'send_email') {
    // 5. exact recipient domain
    if (recipientDomain(args.to) !== EMAIL_DOMAIN) return block(REASON.EGRESS_DENIED);
    // 6. human approval
    if (!approved) return block(REASON.APPROVAL_REQUIRED);
  }

  // 7. safe rendering
  if (tool === 'render_html' && !htmlIsSafe(args.html)) {
    return block(REASON.UNSAFE_OUTPUT);
  }

  return allow();
}

// ---------------------------------------------------------------- server ---
function sendJson(res, status, payload) {
  const data = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Cache-Control': 'no-store',
  });
  res.end(data);
}

const server = http.createServer((req, res) => {
  const path = (req.url || '/').split('?')[0].replace(/\/+$/, '') || '/';

  if (req.method === 'OPTIONS') return sendJson(res, 204, {});
  if (req.method === 'GET' && (path === '/' || path === '/health')) {
    return sendJson(res, 200, {
      status: 'ok',
      endpoint: 'POST /action-firewall',
      tenant: TENANT_ID,
      emailDomain: EMAIL_DOMAIN,
    });
  }
  if (path !== '/action-firewall') return sendJson(res, 404, { error: 'not_found' });
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });

  const chunks = [];
  let size = 0;
  let aborted = false;

  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      aborted = true;
      sendJson(res, 200, block(REASON.INVALID_SCHEMA));
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (aborted) return;
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      return sendJson(res, 200, block(REASON.INVALID_SCHEMA));  // unparseable = schema fault
    }
    let verdict;
    try {
      verdict = evaluate(parsed);
    } catch {
      verdict = block(REASON.INVALID_SCHEMA);                   // fail closed
    }
    sendJson(res, 200, verdict);
  });

  req.on('error', () => {
    if (!aborted && !res.headersSent) sendJson(res, 200, block(REASON.INVALID_SCHEMA));
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`action-firewall listening on :${PORT}  tenant=${TENANT_ID}  domain=${EMAIL_DOMAIN}`);
  });
}

module.exports = { evaluate, htmlIsSafe, recipientDomain, REASON, server };
