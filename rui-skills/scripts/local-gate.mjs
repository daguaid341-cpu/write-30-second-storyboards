#!/usr/bin/env node
// Client only. No local authorization service, permission switch or offline fallback.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { stateRoot, maxBytes, readJson, saveJson, fingerprint, httpsEndpoint, validDigest, validDevice } from './gate-common.mjs';
export { skillRoot, stateRoot, fingerprint } from './gate-common.mjs';
const script = fileURLToPath(import.meta.url);
export const clientFile = path.join(stateRoot, 'client.json');
function validateClient(config) {
  if (!config || config.schema_version !== 2 || !validDigest(config.token) || !validDevice(config.device_id))
    throw new Error('客户端凭证格式无效');
  return httpsEndpoint(config.url);
}
export function importClient(source, target = clientFile) {
  const config = readJson(source);
  validateClient(config);
  if (config.ca_file) throw new Error('导入自定义CA须由管理员单独配置绝对路径');
  fs.mkdirSync(path.dirname(target), {recursive: true, mode: 0o700});
  saveJson(target, config, {exclusive: true});
}
export async function authorize({configPath = process.env.RUI_SKILL_GATE_CONFIG || clientFile,
  digest = fingerprint(), timeoutMs = 5000} = {}) {
  let config, url, ca;
  try {
    config = readJson(configPath); url = validateClient(config);
    if (config.ca_file) {
      if (!path.isAbsolute(config.ca_file)) throw new Error();
      ca = fs.readFileSync(config.ca_file);
    }
  } catch { throw new Error('统一授权客户端未配置或凭证无效，禁止使用 Rui-Skills'); }
  const requestId = randomBytes(16).toString('hex');
  const body = JSON.stringify({skill: 'rui-skills', purpose: 'storyboard', device_id: config.device_id,
    fingerprint: digest, request_id: requestId});
  const response = await new Promise((resolve, reject) => {
    const request = https.request(url, {method: 'POST', agent: false, rejectUnauthorized: true, ...(ca ? {ca} : {}), headers: {
      Authorization: `Bearer ${config.token}`, 'X-Rui-Device': config.device_id,
      'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
    }}, res => {
      let text = '', size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > maxBytes) request.destroy(new Error('invalid_response'));
        else text += chunk.toString('utf8');
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('denied'));
        try { resolve(JSON.parse(text)); } catch { reject(new Error('invalid_response')); }
      });
    });
    const timer = setTimeout(() => request.destroy(new Error('timeout')), timeoutMs);
    request.on('error', reject); request.on('close', () => clearTimeout(timer)); request.end(body);
  }).catch(() => { throw new Error('统一授权未通过（拒绝、连接或证书失败、响应无效），禁止使用 Rui-Skills'); });
  const now = Math.floor(Date.now() / 1000);
  if (!response || response.allowed !== true || response.skill !== 'rui-skills' || response.device_id !== config.device_id ||
      response.fingerprint !== digest || response.request_id !== requestId || !Number.isInteger(response.expires_at) ||
      response.expires_at <= now || response.expires_at > now + 35)
    throw new Error('统一授权响应不匹配或已过期，禁止使用 Rui-Skills');
  return response;
}
export function requireAuthorization() {
  try {
    execFileSync(process.execPath, [script, 'verify'], {
      encoding: 'utf8', windowsHide: true, timeout: 8000, maxBuffer: 16384, stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch { throw new Error('Rui-Skills 本次授权未通过，已停止执行。请检查统一服务器、设备凭证与批准版本。'); }
}
async function main(args) {
  const [command, ...rest] = args;
  if (command === 'verify' && rest.length === 0) console.log(JSON.stringify(await authorize()));
  else if (command === 'fingerprint' && rest.length === 0) console.log(fingerprint());
  else if (command === 'configure-client' && rest.length === 2 && rest[0] === '--from') {
    importClient(path.resolve(rest[1]), process.env.RUI_SKILL_GATE_CONFIG || clientFile);
    console.log('客户端凭证已导入；仍须在线验证通过后才能使用。');
  } else {
    console.log('Client only: verify | fingerprint | configure-client --from FILE');
    if (command && !['--help', '-h'].includes(command)) throw new Error('客户端不提供本机授权或管理命令');
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === script) {
  main(process.argv.slice(2)).catch(() => {
    console.error('操作失败或授权未通过；请检查服务器凭证与配置。不会启动本机服务、离线放行或输出密钥。');
    process.exitCode = 1;
  });
}
