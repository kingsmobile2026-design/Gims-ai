/**
 * block.js — Gims AI 입력 방어 모듈 (의존성 없음)
 *
 * 차단 대상:
 *  - SQL / NoSQL 인젝션
 *  - XSS (스크립트·이벤트 핸들러)
 *  - 경로 순회 (path traversal)
 *  - 명령어 인젝션
 *  - 프로토타입 오염
 *  - 헤더/CRLF 인젝션
 *  - 과도한 페이로드
 *
 * 사용:
 *   const block = require('./block');
 *   // 요청 본문 검사
 *   const bad = block.scan(JSON.stringify(body));
 *   if (bad) return fail(res, 400, '차단된 입력이 포함되어 있습니다.');
 *   // 또는 미들웨어 스타일
 *   if (block.guard(req, res)) return; // true면 이미 응답 보냄
 */

'use strict';

// ---------- 패턴 정의 ----------
const PATTERNS = {
  // SQL 인젝션
  sql: [
    /(\b)(UNION\s+(ALL\s+)?SELECT|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|ALTER\s+TABLE|TRUNCATE\s+TABLE|CREATE\s+(TABLE|DATABASE)|EXEC(\s|\(|ute)|EXECUTE\s|xp_cmdshell|sp_executesql)(\b)/i,
    /('|")\s*(OR|AND)\s*('|")?\s*\d+\s*(=|<|>|LIKE)\s*('|")?\s*\d+/i,
    /('|")\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    /(--|#|\/\*|\*\/)\s*$/m,
    /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\b/i,
    /\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|PG_CATALOG|MYSQL\.)\b/i,
    /\b(BENCHMARK|SLEEP|WAITFOR\s+DELAY|PG_SLEEP)\s*\(/i,
    /\bLOAD_FILE\s*\(|INTO\s+(OUT|DUMP)FILE\b/i,
  ],

  // NoSQL 인젝션 (MongoDB 등)
  nosql: [
    /\$where\b/i,
    /\$ne\b|\$gt\b|\$gte\b|\$lt\b|\$lte\b|\$in\b|\$nin\b|\$regex\b|\$exists\b|\$or\b|\$and\b|\$not\b|\$nor\b|\$expr\b/i,
    /\{\s*["']?\$/,
  ],

  // XSS
  xss: [
    /<\s*script\b/i,
    /<\s*\/\s*script\s*>/i,
    /javascript\s*:/i,
    /vbscript\s*:/i,
    /on(error|load|click|mouse|focus|blur|submit|change|input|key|touch|drag|drop|scroll|wheel|pointer|animation|transition)\s*=/i,
    /<\s*(iframe|object|embed|applet|meta|link|base|form|svg|math)\b/i,
    /expression\s*\(/i,
    /url\s*\(\s*['"]?\s*javascript:/i,
    /data\s*:\s*text\/html/i,
    /\bsrcdoc\s*=/i,
  ],

  // 경로 순회
  path: [
    /\.\.[\\/]/,
    /(?:^|[\\/])(?:etc|windows|system32|proc|sys)[\\/]/i,
    /%2e%2e[\\/]|%252e%252e/i,
    /\0/,
  ],

  // 명령어 인젝션
  cmd: [
    /[;&|`]\s*(?:ls|cat|id|whoami|uname|curl|wget|nc|ncat|bash|sh|cmd|powershell|rm|chmod|chown|kill)\b/i,
    /\$\([^)]+\)|`[^`]+`/,
    /\|\s*(?:bash|sh|cmd|powershell)\b/i,
  ],

  // 프로토타입 오염
  proto: [
    /__proto__/i,
    /constructor\s*[.\[]\s*prototype/i,
    /\["prototype"\]|\['prototype'\]/,
  ],

  // 헤더 / CRLF 인젝션
  crlf: [
    /[\r\n]\s*(?:Set-Cookie|Location|Content-|X-)/i,
    /%0d%0a|%0a%0d|\\r\\n|\\n\\r/i,
  ],
};

const ALL_KEYS = Object.keys(PATTERNS);

// 허용 문자만 남기는 화이트리스트 (아이디·짧은 토큰용)
const SAFE_ID = /^[a-z0-9_가-힣]{1,64}$/i;
const SAFE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SAFE_HEX = /^[a-f0-9]+$/i;

/**
 * 문자열 한 덩어리를 스캔. 탐지되면 { type, pattern } 반환, 아니면 null
 */
function scan(input, opts = {}) {
  if (input == null) return null;
  const str = typeof input === 'string' ? input : String(input);
  if (!str) return null;

  const maxLen = opts.maxLen != null ? opts.maxLen : 2_000_000;
  if (str.length > maxLen) return { type: 'size', pattern: 'payload too large' };

  const types = opts.types || ALL_KEYS;
  for (const type of types) {
    const list = PATTERNS[type];
    if (!list) continue;
    for (const re of list) {
      if (re.test(str)) return { type, pattern: String(re) };
    }
  }
  return null;
}

/**
 * 객체/배열을 재귀 스캔 (키 이름 + 값)
 * 프로토타입 오염 키는 즉시 차단
 */
function scanDeep(value, opts = {}, depth = 0) {
  if (depth > (opts.maxDepth || 12)) return { type: 'depth', pattern: 'too deep' };
  if (value == null) return null;

  if (typeof value === 'string') return scan(value, opts);
  if (typeof value === 'number' || typeof value === 'boolean') return null;

  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = scanDeep(item, opts, depth + 1);
      if (hit) return hit;
    }
    return null;
  }

  if (typeof value === 'object') {
    // 위험 키
    for (const k of Object.keys(value)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
        return { type: 'proto', pattern: k };
      }
      const keyHit = scan(k, { ...opts, types: ['sql', 'nosql', 'proto', 'crlf'] });
      if (keyHit) return keyHit;
      const valHit = scanDeep(value[k], opts, depth + 1);
      if (valHit) return valHit;
    }
  }
  return null;
}

/**
 * HTML 이스케이프 (출력 시 XSS 완화)
 */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * 경로 정규화 + 순회 차단. base 밖이면 null
 */
function safePath(baseDir, userPath) {
  const path = require('path');
  if (userPath == null || typeof userPath !== 'string') return null;
  if (scan(userPath, { types: ['path', 'crlf'] })) return null;
  const resolved = path.resolve(baseDir, userPath);
  const base = path.resolve(baseDir);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) return null;
  return resolved;
}

/**
 * 아이디 / 이메일 / 단순 토큰 검증
 */
function isSafeId(s) {
  return typeof s === 'string' && SAFE_ID.test(s);
}
function isSafeEmail(s) {
  return typeof s === 'string' && s.length <= 254 && SAFE_EMAIL.test(s);
}
function isSafeHex(s, min = 1, max = 128) {
  return typeof s === 'string' && s.length >= min && s.length <= max && SAFE_HEX.test(s);
}

/**
 * 위험 키 제거한 얕은/깊은 복사 (프로토타입 오염 방지)
 */
function sanitizeObject(input, depth = 0) {
  if (input == null || typeof input !== 'object') return input;
  if (depth > 12) return null;
  if (Array.isArray(input)) return input.map(v => sanitizeObject(v, depth + 1));
  const out = Object.create(null);
  for (const k of Object.keys(input)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = sanitizeObject(input[k], depth + 1);
  }
  return out;
}

/**
 * HTTP 요청 가드. 위험하면 400 JSON 응답 후 true 반환.
 * server.js 안에서:
 *   if (block.guard(req, res, bodyObj)) return;
 */
function guard(req, res, body, opts = {}) {
  const targets = [];
  if (req.url) targets.push(req.url);
  if (req.headers) {
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') targets.push(k, v);
      else if (Array.isArray(v)) targets.push(k, ...v);
    }
  }
  if (body !== undefined) {
    const hit = scanDeep(body, opts);
    if (hit) {
      _reject(res, hit);
      return true;
    }
  }
  for (const t of targets) {
    const hit = scan(t, { ...opts, maxLen: opts.headerMaxLen || 8192 });
    if (hit) {
      _reject(res, hit);
      return true;
    }
  }
  return false;
}

function _reject(res, hit) {
  if (res.headersSent) return;
  const payload = JSON.stringify({
    error: {
      message: '차단된 입력이 포함되어 있습니다.',
      code: 'BLOCKED',
      type: hit.type,
    },
  });
  res.writeHead(400, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
  if (typeof console !== 'undefined' && console.warn) {
    console.warn('[block] rejected', hit.type, hit.pattern && hit.pattern.slice(0, 80));
  }
}

/**
 * 보안 응답 헤더 세트
 */
function securityHeaders(res) {
  const h = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-XSS-Protection': '0',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; base-uri 'self'; form-action 'self'",
  };
  for (const [k, v] of Object.entries(h)) {
    if (!res.headersSent) res.setHeader(k, v);
  }
}

/**
 * IP별 간단 레이트 리밋 (메모리). 반환: 초과면 true
 */
const _buckets = new Map();
function rateLimit(ip, { windowMs = 60_000, max = 120 } = {}) {
  const now = Date.now();
  let b = _buckets.get(ip);
  if (!b || now - b.start > windowMs) {
    b = { start: now, n: 0 };
    _buckets.set(ip, b);
  }
  b.n += 1;
  if (_buckets.size > 20_000) {
    for (const [k, v] of _buckets) {
      if (now - v.start > windowMs * 2) _buckets.delete(k);
    }
  }
  return b.n > max;
}

module.exports = {
  scan,
  scanDeep,
  escapeHtml,
  safePath,
  isSafeId,
  isSafeEmail,
  isSafeHex,
  sanitizeObject,
  guard,
  securityHeaders,
  rateLimit,
  PATTERNS,
};
