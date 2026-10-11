import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import { authorize, fingerprint, skillRoot, importClient } from './local-gate.mjs';
import { setup, issueDevice, updatePolicy } from './authorization-server.mjs';
import { startFixture, makeTestTLS } from './gate-test-fixture.mjs';

const fixture = await startFixture();
const originalPolicy = JSON.parse(fs.readFileSync(fixture.policyPath, 'utf8'));
const originalClient = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
const writePolicy = policy => fs.writeFileSync(fixture.policyPath, JSON.stringify(policy));
const writeClient = config => fs.writeFileSync(fixture.configPath, JSON.stringify(config));
const verify = options => authorize({configPath: fixture.configPath, ...options});
let checks = 0;
async function rejects(fn) { await assert.rejects(fn); checks++; }
const cli = (...args) => spawnSync(process.execPath, [path.join(skillRoot, 'scripts/production.mjs'), ...args], {
  encoding: 'utf8', windowsHide: true, env: {...process.env, RUI_SKILL_GATE_CONFIG: fixture.configPath},
});
try {
  const receipt = await verify(); assert.equal(receipt.allowed, true); checks++;
  assert.equal(receipt.fingerprint, fingerprint()); checks++;
  assert.notEqual((await verify()).request_id, receipt.request_id); checks++;
  assert.throws(() => setup({directory: fixture.directory, digest: fingerprint()})); checks++;
  await rejects(() => authorize({configPath: path.join(fixture.directory, 'missing.json')}));
  writeClient({...originalClient, token: '0'.repeat(64)});
  await rejects(() => verify()); writeClient(originalClient);
  writeClient({...originalClient, device_id: 'unknown-device'});
  await rejects(() => verify()); writeClient(originalClient);
  // Two independent device credentials, no plaintext token in server policy.
  const second = path.join(fixture.directory, 'second.json');
  issueDevice({policyPath: fixture.policyPath, deviceId: 'test-b', url: originalClient.url, output: second});
  const secondConfig = JSON.parse(fs.readFileSync(second));
  secondConfig.ca_file = originalClient.ca_file;
  fs.writeFileSync(second, JSON.stringify(secondConfig));
  assert.notEqual(secondConfig.token, originalClient.token); checks++;
  assert.equal(fs.readFileSync(fixture.policyPath, 'utf8').includes(secondConfig.token), false); checks++;
  updatePolicy(fixture.policyPath, 'device-disable', 'test-a');
  await rejects(() => verify());
  assert.equal((await authorize({configPath: second})).device_id, 'test-b'); checks++;
  updatePolicy(fixture.policyPath, 'device-enable', 'test-a');
  assert.equal((await verify()).allowed, true); checks++;
  writeClient({...originalClient, device_id: 'test-b'});
  await rejects(() => verify()); writeClient(originalClient);
  const rotated = path.join(fixture.directory, 'rotated.json');
  issueDevice({policyPath: fixture.policyPath, deviceId: 'test-a', url: originalClient.url, output: rotated, rotate: true});
  await rejects(() => verify());
  const rotatedConfig = {...JSON.parse(fs.readFileSync(rotated)), ca_file: originalClient.ca_file};
  writeClient(rotatedConfig); assert.equal((await verify()).allowed, true); checks++;
  writeClient(originalClient); writePolicy(originalPolicy);
  updatePolicy(fixture.policyPath, 'revoke-version', fingerprint());
  await rejects(() => verify());
  updatePolicy(fixture.policyPath, 'approve-version', fingerprint());
  assert.equal((await verify()).allowed, true); checks++;
  await rejects(() => verify({digest: '0'.repeat(64)}));
  writePolicy({...originalPolicy, enabled: false});
  await rejects(() => verify());
  const output = path.join(fixture.directory, 'must-not-exist.md');
  const denied = cli('export-text', fixture.directory, '--out', output);
  assert.notEqual(denied.status, 0); assert.match(denied.stderr, /授权未通过/);
  assert.equal(fs.existsSync(output), false); checks++;
  for (const args of [['check', fixture.directory], ['report', fixture.directory], ['run', 'novel-storyboard', '--help']]) {
    assert.match(cli(...args).stderr, /授权未通过/); checks++;
  }
  writePolicy(originalPolicy);
  assert.equal((await verify()).allowed, true); checks++;
  fs.writeFileSync(fixture.policyPath, '{'); await rejects(() => verify()); writePolicy(originalPolicy);
  writeClient({...originalClient, url: 'http://example.com/v1/skills/authorize'});
  await rejects(() => verify()); writeClient(originalClient);
  writeClient({...originalClient, url: originalClient.url.replace('https:', 'http:')});
  await rejects(() => verify()); writeClient(originalClient);
  // No local setup/permission commands survive in the client CLI.
  for (const command of ['setup', 'serve', 'allow', 'approve-current']) {
    const result = spawnSync(process.execPath, [path.join(skillRoot, 'scripts/local-gate.mjs'), command], {encoding: 'utf8', windowsHide: true});
    assert.notEqual(result.status, 0); checks++;
  }
  const cleanCredential = {...originalClient}; delete cleanCredential.ca_file;
  const importSource = path.join(fixture.directory, 'import.json'), importTarget = path.join(fixture.directory, 'installed.json');
  fs.writeFileSync(importSource, JSON.stringify(cleanCredential));
  importClient(importSource, importTarget); checks++;
  assert.throws(() => importClient(importSource, importTarget)); checks++;
  // Untrusted TLS is rejected even when a process environment asks Node to ignore it.
  writeClient(cleanCredential);
  const oldTlsEnv = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try { await rejects(() => verify()); }
  finally { if (oldTlsEnv === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = oldTlsEnv; }
  writeClient(originalClient);

  // Bad responses are rejected even when HTTP succeeds; no redirects or stale receipts.
  let mode = 'malformed';
  const fake = https.createServer(fixture.tls, (req, res) => {
    let body = ''; req.on('data', b => body += b);
    req.on('end', () => {
      if (mode === 'timeout') return;
      if (mode === 'redirect') { res.writeHead(302, {Location: originalClient.url}); res.end(); return; }
      if (mode === 'malformed') { res.end('{'); return; }
      const data = JSON.parse(body);
      const reply = {allowed: true, skill: data.skill, device_id: data.device_id, fingerprint: data.fingerprint,
        request_id: data.request_id, expires_at: Math.floor(Date.now() / 1000) + 30};
      if (mode === 'nonce') reply.request_id = '0'.repeat(32);
      if (mode === 'expired') reply.expires_at = 1;
      if (mode === 'string') reply.allowed = 'true';
      if (mode === 'digest') reply.fingerprint = '0'.repeat(64);
      if (mode === 'device') reply.device_id = 'test-b';
      if (mode === 'oversized') reply.extra = 'x'.repeat(5000);
      res.end(JSON.stringify(reply));
    });
  });
  await new Promise(resolve => fake.listen(0, '127.0.0.1', resolve));
  try {
    writeClient({...originalClient, url: `https://127.0.0.1:${fake.address().port}/v1/skills/authorize`});
    for (mode of ['malformed', 'redirect', 'nonce', 'expired', 'string', 'digest', 'device', 'oversized', 'timeout'])
      await rejects(() => verify({timeoutMs: 100}));
  } finally { fake.closeAllConnections(); await new Promise(resolve => fake.close(resolve)); }
  await rejects(() => verify()); // Closed port, following an earlier successful grant.
  const wrongDir = path.join(fixture.directory, 'wrong-host'); fs.mkdirSync(wrongDir);
  const wrongTLS = makeTestTLS(wrongDir, {wrongHostname: true});
  const wrong = https.createServer(wrongTLS, (_, res) => res.end('{}'));
  await new Promise(resolve => wrong.listen(0, '127.0.0.1', resolve));
  try {
    writeClient({...originalClient, ca_file: wrongTLS.certPath, url: `https://127.0.0.1:${wrong.address().port}/v1/skills/authorize`});
    await rejects(() => verify());
  } finally { wrong.closeAllConnections(); await new Promise(resolve => wrong.close(resolve)); }
  assert.ok(!JSON.stringify(receipt).includes(originalClient.token)); checks++;
  console.log(`PASS ${checks} centralized HTTPS authorization checks; denial never generates output`);
} finally { await fixture.stop(); }
