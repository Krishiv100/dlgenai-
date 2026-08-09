'use strict';
// Vercel / Netlify-style serverless adapter. Reuses the exact same decision
// logic as server.js so local and deployed behaviour cannot drift.
const { evaluate, REASON } = require('../server.js');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'method_not_allowed' });
  }

  let body = req.body;
  if (typeof body === 'string' || Buffer.isBuffer(body)) {
    try {
      body = JSON.parse(body.toString('utf8'));
    } catch {
      return res.status(200).json({ decision: 'block', reason: REASON.INVALID_SCHEMA });
    }
  }
  if (body === undefined) {
    return res.status(200).json({ decision: 'block', reason: REASON.INVALID_SCHEMA });
  }

  let verdict;
  try {
    verdict = evaluate(body);
  } catch {
    verdict = { decision: 'block', reason: REASON.INVALID_SCHEMA };
  }
  return res.status(200).json(verdict);
};
