#!/usr/bin/env node
// Server-owner administration only. Never distribute server policy to client machines.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { endpoint, maxBytes, validDigest, validDevice, validPort, tokenHash,
  readJson, saveJson, httpsEndpoint, skillRoot } from './gate-common.mjs';
const file = fileURLToPath(import.meta.url);
export const serverStateRoot = path.join(skillRoot, '.authorization-server');
export function loadPolicy(policyPath) {
  const p = readJson(policyPath);
  if (!p || p.schema_version !== 2 || typeof p.enabled !== 'boolean' || !validPort(p.port) ||
      !Array.isArray(p.approved_fingerprints) || !p.approved_fingerprints.every(validDigest) ||
      !p.devices || typeof p.devices !== 'object' || Array.isArray(p.devices)) throw new Error('服务策略无效');
  for (const [id, device] of Object.entries(p.devices)) {
    if (!validDevice(id) || !device || !validDigest(device.token_hash) || typeof device.enabled !== 'boolean')
      throw new Error('设备策略无效');
  }
  return p;
}
export function setup({directory = serverStateRoot, port = 8765, digest} = {}) {
  if (!validPort(port) || !validDigest(digest)) throw new Error('需要有效端口和明确批准的文件摘要');
  fs.mkdirSync(directory, {recursive: true, mode: 0o700});
  const policyPath = path.join(directory, 'server.json');
  saveJson(policyPath, {schema_version: 2, enabled: true, port, approved_fingerprints: [digest], devices: {}}, {exclusive: true});
  return policyPath;
}
export function issueDevice({policyPath, deviceId, url, output, rotate = false}) {
  if (!validDevice(deviceId)) throw new Error('设备ID无效');
  httpsEndpoint(url);
  const p = loadPolicy(policyPath), exists = Object.hasOwn(p.devices, deviceId);
  if (rotate ? !exists : exists) throw new Error('设备已存在或轮换目标不存在');
  if (fs.existsSync(output)) throw new Error('凭证输出文件已存在');
  const token = randomBytes(32).toString('hex');
  saveJson(output, {schema_version: 2, url, device_id: deviceId, token}, {exclusive: true});
  p.devices[deviceId] = {enabled: exists ? p.devices[deviceId].enabled : true, token_hash: tokenHash(token)};
  saveJson(policyPath, p);
  return {device_id: deviceId};
}
export function updatePolicy(policyPath, command, value) {
  const p = loadPolicy(policyPath);
  if (['device-enable', 'device-disable'].includes(command)) {
    if (!validDevice(value) || !Object.hasOwn(p.devices, value)) throw new Error('设备不存在');
    p.devices[value].enabled = command === 'device-enable';
  } else if (['approve-version', 'revoke-version'].includes(command)) {
    if (!validDigest(value)) throw new Error('文件摘要无效');
    p.approved_fingerprints = command === 'approve-version' ? [...new Set([...p.approved_fingerprints, value])]
      : p.approved_fingerprints.filter(x => x !== value);
  } else if (['allow', 'deny'].includes(command)) p.enabled = command === 'allow';
  else throw new Error('未知管理操作');
  saveJson(policyPath, p);
}
export function makeServer(policyPath, {tls} = {}) {
  const handler = (req, res) => {
    const reply = (code, body) => {
      res.writeHead(code, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'POST' || req.url !== endpoint) return reply(404, {allowed: false});
    let policy;
    try { policy = loadPolicy(policyPath); } catch { return reply(503, {allowed: false}); }
    const deviceId = req.headers['x-rui-device'], auth = req.headers.authorization;
    if (!validDevice(deviceId) || !Object.hasOwn(policy.devices, deviceId) || typeof auth !== 'string' ||
        !/^Bearer [a-f0-9]{64}$/.test(auth)) return reply(401, {allowed: false});
    const device = policy.devices[deviceId];
    if (!timingSafeEqual(Buffer.from(tokenHash(auth.slice(7)), 'hex'), Buffer.from(device.token_hash, 'hex')))
      return reply(401, {allowed: false});
    let body = '', count = 0;
    req.on('data', chunk => {
      count += chunk.length;
      if (count > maxBytes) { req.destroy(); return; }
      body += chunk.toString('utf8');
    });
    req.on('end', () => {
      let data;
      try { data = JSON.parse(body); } catch { return reply(400, {allowed: false}); }
      if (!data || data.skill !== 'rui-skills' || data.purpose !== 'storyboard' || data.device_id !== deviceId ||
          !validDigest(data.fingerprint) || typeof data.request_id !== 'string' || !/^[a-f0-9]{32}$/.test(data.request_id))
        return reply(400, {allowed: false});
      try { policy = loadPolicy(policyPath); } catch { return reply(503, {allowed: false}); }
      const current = policy.devices[deviceId];
      if (policy.enabled !== true || !current || current.enabled !== true || current.token_hash !== device.token_hash ||
          !policy.approved_fingerprints.includes(data.fingerprint)) return reply(403, {allowed: false});
      reply(200, {allowed: true, skill: data.skill, device_id: deviceId, fingerprint: data.fingerprint,
        request_id: data.request_id, expires_at: Math.floor(Date.now() / 1000) + 30});
    });
    req.on('error', () => {});
  };
  const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
  server.requestTimeout = 5000; server.headersTimeout = 5000; server.timeout = 5000; server.maxHeadersCount = 20;
  return server;
}
async function main(args) {
  const [command, ...rest] = args;
  const flags = {};
  const allowedFlags = ['--state-dir', '--port', '--fingerprint', '--device', '--url', '--out', '--host'];
  for (let i = 0; i < rest.length; i += 2) {
    if (!allowedFlags.includes(rest[i]) || !rest[i + 1] || Object.hasOwn(flags, rest[i])) throw new Error('参数无效');
    flags[rest[i]] = rest[i + 1];
  }
  const directory = path.resolve(flags['--state-dir'] || serverStateRoot), policyPath = path.join(directory, 'server.json');
  if (command === 'init') {
    setup({directory, port: flags['--port'] ? Number(flags['--port']) : 8765, digest: flags['--fingerprint']});
    console.log('服务策略已初始化；尚未授权任何设备。');
  } else if (command === 'serve') {
    const p = loadPolicy(policyPath), host = flags['--host'] || '127.0.0.1';
    if (!isIP(host)) throw new Error('监听地址必须是IP地址');
    const server = makeServer(policyPath);
    server.on('error', () => { console.error('授权服务启动失败，请检查配置和端口。'); process.exitCode = 1; });
    server.listen(p.port, host, () => console.log(`Authorization backend listening on ${host}:${p.port}; HTTPS proxy required`));
  } else if (['add-device', 'rotate-device'].includes(command)) {
    if (!flags['--out']) throw new Error('缺少凭证输出路径');
    issueDevice({policyPath, deviceId: flags['--device'], url: flags['--url'],
      output: path.resolve(flags['--out']), rotate: command === 'rotate-device'});
    console.log('设备凭证已写入指定文件；不要公开或分享给其他设备。');
  } else if (command === 'list-devices') {
    console.log(JSON.stringify(Object.entries(loadPolicy(policyPath).devices).map(([device_id, d]) => ({device_id, enabled: d.enabled}))));
  } else if (['allow', 'deny', 'device-enable', 'device-disable', 'approve-version', 'revoke-version'].includes(command)) {
    updatePolicy(policyPath, command, command.includes('version') ? flags['--fingerprint'] : flags['--device']);
    console.log('服务器策略已更新；后续验证即时生效。');
  } else {
    console.log('Server only: init|serve|add-device|rotate-device|list-devices|device-enable|device-disable|allow|deny|approve-version|revoke-version');
    if (command && !['--help', '-h'].includes(command)) process.exitCode = 1;
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === file) {
  main(process.argv.slice(2)).catch(() => { console.error('服务器管理操作失败；请检查参数、策略及输出路径。不会输出凭证。'); process.exitCode = 1; });
}
