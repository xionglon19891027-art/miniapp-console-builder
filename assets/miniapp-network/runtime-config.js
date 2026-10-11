/* Reference HTTP configuration; no credentials and no stored endpoint fallback. */
function resolveConfig(config) {
  if (!config || !['development', 'experience', 'release'].includes(config.mode)) throw new Error('INVALID_MODE');
  if (Object.keys(config).some(k => !['mode', 'apiBase'].includes(k))) throw new Error('UNKNOWN_CONFIG');
  const base = config.apiBase;
  if (typeof base !== 'string' || /[\s\\?#%@]/.test(base)) throw new Error('INVALID_API_BASE');
  // Deliberately accept conventional DNS/IPv4 only. IPv6 requires a reviewed adapter.
  const m = /^(https?):\/\/([A-Za-z0-9.-]+)(?::([0-9]+))?(\/[^?#]*)?$/.exec(base);
  if (!m || (m[3] && (+m[3] < 1 || +m[3] > 65535))) throw new Error('INVALID_API_BASE');
  const host = m[2].toLowerCase();
  if ((m[4] || '').split('/').some(p => p === '.' || p === '..')) throw new Error('INVALID_API_BASE');
  if (config.mode !== 'development') {
    if (m[1] !== 'https') throw new Error('HTTPS_REQUIRED');
    // Public DNS names only; avoid alternate numeric representations of local IPs.
    if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(host) || /(?:^|\.)(?:localhost|local|internal|test|invalid|example)$/.test(host) || /(?:^|\.)example\.(?:com|org|net)$/.test(host)) throw new Error('PUBLIC_HOST_REQUIRED');
  }
  return Object.freeze({ mode: config.mode, apiBase: base.replace(/\/+$/, '') });
}
module.exports = { resolveConfig };
