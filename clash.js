const { URL } = require('url');

function yamlString(value) {
  const str = String(value ?? '');
  return JSON.stringify(str);
}

function safeName(name, fallback) {
  const cleaned = String(name || '').trim();
  return cleaned || fallback;
}

function parseVless(line, fallbackName) {
  const u = new URL(line);
  const params = u.searchParams;
  const host = params.get('host') || params.get('sni') || u.hostname;
  const path = params.get('path') || '/';
  const security = params.get('security') || '';
  const proxy = {
    name: safeName(decodeURIComponent(u.hash.replace(/^#/, '')), fallbackName),
    type: 'vless',
    server: u.hostname,
    port: Number(u.port || 443),
    uuid: decodeURIComponent(u.username),
    tls: security === 'tls',
    network: params.get('type') || 'tcp',
  };
  if (params.get('sni')) proxy.servername = params.get('sni');
  if (params.get('fp')) proxy['client-fingerprint'] = params.get('fp');
  if (proxy.network === 'ws') {
    proxy['ws-opts'] = { path, headers: { Host: host } };
  }
  return proxy;
}

function parseTrojan(line, fallbackName) {
  const u = new URL(line);
  const params = u.searchParams;
  const host = params.get('host') || params.get('sni') || u.hostname;
  const path = params.get('path') || '/';
  const security = params.get('security') || '';
  const proxy = {
    name: safeName(decodeURIComponent(u.hash.replace(/^#/, '')), fallbackName),
    type: 'trojan',
    server: u.hostname,
    port: Number(u.port || 443),
    password: decodeURIComponent(u.username),
    tls: security === 'tls' || security === '',
    network: params.get('type') || 'tcp',
  };
  if (params.get('sni')) proxy.sni = params.get('sni');
  if (params.get('fp')) proxy['client-fingerprint'] = params.get('fp');
  if (proxy.network === 'ws') {
    proxy['ws-opts'] = { path, headers: { Host: host } };
  }
  return proxy;
}

function parseVmess(line, fallbackName) {
  const raw = line.replace(/^vmess:\/\//, '').trim();
  const decoded = Buffer.from(raw, 'base64').toString('utf-8');
  const v = JSON.parse(decoded);
  const proxy = {
    name: safeName(v.ps, fallbackName),
    type: 'vmess',
    server: v.add,
    port: Number(v.port || 443),
    uuid: v.id,
    alterId: Number(v.aid || 0),
    cipher: v.scy || 'auto',
    tls: v.tls === 'tls',
    network: v.net || 'tcp',
  };
  if (v.sni) proxy.servername = v.sni;
  if (v.fp) proxy['client-fingerprint'] = v.fp;
  if (proxy.network === 'ws') {
    proxy['ws-opts'] = { path: v.path || '/', headers: { Host: v.host || v.add } };
  }
  return proxy;
}

function renderValue(value, indent = 0) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return value.map(item => `${pad}- ${renderValue(item, indent + 2).replace(/^\s+/, '')}`).join('\n');
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, val]) => {
      if (val && typeof val === 'object') {
        return `${pad}${key}:\n${renderValue(val, indent + 2)}`;
      }
      return `${pad}${key}: ${renderValue(val, indent + 2)}`;
    }).join('\n');
  }
  if (typeof value === 'string') return yamlString(value);
  return String(value);
}

function proxyToYaml(proxy) {
  const entries = Object.entries(proxy);
  return entries.map(([key, val], idx) => {
    const prefix = idx === 0 ? '- ' : '  ';
    if (val && typeof val === 'object') {
      return `${prefix}${key}:\n${renderValue(val, 4)}`;
    }
    return `${prefix}${key}: ${renderValue(val, 2)}`;
  }).join('\n');
}

function buildClashConfig(subTxt) {
  const lines = subTxt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const proxies = [];
  lines.forEach((line, index) => {
    try {
      if (line.startsWith('vless://')) proxies.push(parseVless(line, `vless-${index + 1}`));
      else if (line.startsWith('vmess://')) proxies.push(parseVmess(line, `vmess-${index + 1}`));
      else if (line.startsWith('trojan://')) proxies.push(parseTrojan(line, `trojan-${index + 1}`));
    } catch (err) {
      console.error(`Skip invalid proxy line ${index + 1}: ${err.message}`);
    }
  });

  const seen = new Map();
  proxies.forEach((proxy) => {
    const base = proxy.name;
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    if (count > 0) proxy.name = `${base}-${count + 1}`;
  });
  const names = proxies.map(p => p.name);

  return [
    'mixed-port: 7890',
    'allow-lan: true',
    'mode: rule',
    'log-level: info',
    'external-controller: 127.0.0.1:9090',
    '',
    'proxies:',
    proxies.length ? proxies.map(proxyToYaml).join('\n') : '[]',
    '',
    'proxy-groups:',
    '- name: PROXY',
    '  type: select',
    '  proxies:',
    ...names.map(name => `  - ${yamlString(name)}`),
    '  - DIRECT',
    '',
    'rules:',
    '- MATCH,PROXY',
    '',
  ].join('\n');
}

module.exports = { buildClashConfig };
