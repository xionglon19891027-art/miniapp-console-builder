const { resolveConfig } = require('./runtime-config');
function failure(code, status, uncertain) {
  const e = new Error(code); e.code = code; e.status = status; e.uncertain = uncertain; return e;
}
function validPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\s#]/.test(path)) return false;
  let decoded;
  try { decoded = decodeURIComponent(path.split('?')[0]); } catch (_) { return false; }
  return !/[\\%\x00-\x20]/.test(decoded) && !decoded.startsWith('//') && !decoded.split('/').some(s => s === '.' || s === '..');
}
function createClient({ wx, config, getSessionToken, onUnauthorized }) {
  const resolved = resolveConfig(config);
  if (!wx || typeof wx.request !== 'function') throw new Error('WX_REQUIRED');
  function request(method, path, data) {
    return new Promise((resolve, reject) => {
      if (!validPath(path)) { reject(failure('INVALID_PATH', 0, false)); return; }
      const token = getSessionToken ? getSessionToken() : '';
      if (typeof token !== 'string' || /[\r\n]/.test(token)) { reject(failure('INVALID_SESSION', 0, false)); return; }
      const header = { 'content-type': 'application/json' };
      if (token) header.Authorization = 'Bearer ' + token;
      let settled = false;
      const fail = () => {
        if (settled) return; settled = true;
        reject(failure(method === 'GET' ? 'NETWORK_ERROR' : 'RESULT_UNKNOWN', 0, method !== 'GET'));
      };
      try {
        wx.request({ url: resolved.apiBase + path, method, data, header, timeout: 30000,
          success(res) {
            if (settled) return; settled = true;
            const status = Number(res.statusCode);
            if (status >= 200 && status < 300) { resolve(res.data); return; }
            // Retain only a bounded machine error code; never reflect raw server logs.
            const raw = res.data && res.data.code;
            const code = typeof raw === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(raw) ? raw : 'HTTP_ERROR';
            const err = failure(code, status, method !== 'GET' && status >= 500);
            if (status === 401 && onUnauthorized) { try { onUnauthorized(err); } catch (_) {} }
            reject(err);
          }, fail
        });
      } catch (_) { fail(); }
    });
  }
  return Object.freeze({ get: path => request('GET', path), post: (path, data) => request('POST', path, data) });
}
module.exports = { createClient };
