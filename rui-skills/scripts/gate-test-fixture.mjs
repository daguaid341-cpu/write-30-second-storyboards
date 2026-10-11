// Isolated real loopback server for tests; never touches the owner's configuration.
import fs from 'node:fs';
import path from 'node:path';
import { fork, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setup, makeServer, issueDevice } from './authorization-server.mjs';
import { skillRoot, fingerprint } from './gate-common.mjs';
const file = fileURLToPath(import.meta.url);
const testRoot = path.resolve(skillRoot, '../output/gate-tests');

export function makeTestTLS(directory, {wrongHostname = false} = {}) {
  const openssl = process.env.OPENSSL || (process.platform === 'win32' && fs.existsSync('C:/Program Files/Git/usr/bin/openssl.exe')
    ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl');
  const key = path.join(directory, 'test-only.key'), cert = path.join(directory, 'test-only.crt');
  const conf = path.join(directory, 'openssl.cnf');
  fs.writeFileSync(conf, '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nsubjectAltName=' + (wrongHostname ? 'DNS:wrong.invalid' : 'DNS:localhost,IP:127.0.0.1') + '\n');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', conf, '-keyout', key, '-out', cert],
    {windowsHide: true, stdio: 'pipe'});
  return {key: fs.readFileSync(key), cert: fs.readFileSync(cert), certPath: cert};
}

export async function startFixture() {
  fs.mkdirSync(testRoot, {recursive: true});
  const directory = fs.mkdtempSync(path.join(testRoot, 'run-'));
  setup({directory, digest: fingerprint()});
  makeTestTLS(directory);
  issueDevice({policyPath: path.join(directory, 'server.json'), deviceId: 'test-a',
    url: 'https://127.0.0.1:8765/v1/skills/authorize', output: path.join(directory, 'client.json')});
  const child = fork(file, ['serve', directory], {stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true});
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error('Test gate startup timed out')); }, 5000);
      child.once('message', msg => { clearTimeout(timer); msg.ready ? resolve() : reject(new Error('Test gate failed')); });
      child.once('error', err => { clearTimeout(timer); reject(err); });
      child.once('exit', () => { clearTimeout(timer); reject(new Error('Test gate exited')); });
    });
  } catch (error) { child.kill(); throw error; }
  return {
    directory, configPath: path.join(directory, 'client.json'), policyPath: path.join(directory, 'server.json'),
    tls: {key: fs.readFileSync(path.join(directory, 'test-only.key')), cert: fs.readFileSync(path.join(directory, 'test-only.crt'))},
    async stop() {
      await new Promise(resolve => { if (child.exitCode !== null) return resolve(); child.once('exit', resolve); child.kill(); });
      const target = path.resolve(directory);
      if (!target.startsWith(testRoot + path.sep)) throw new Error('Invalid test cleanup target');
      fs.rmSync(target, {recursive: true, force: true});
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === file && process.argv[2] === 'serve') {
  const directory = process.argv[3];
  const server = makeServer(path.join(directory, 'server.json'), {tls: {
    key: fs.readFileSync(path.join(directory, 'test-only.key')), cert: fs.readFileSync(path.join(directory, 'test-only.crt')),
  }});
  server.listen(0, '127.0.0.1', () => {
    const clientPath = path.join(directory, 'client.json');
    const config = JSON.parse(fs.readFileSync(clientPath, 'utf8'));
    config.url = `https://127.0.0.1:${server.address().port}/v1/skills/authorize`;
    config.ca_file = path.join(directory, 'test-only.crt');
    fs.writeFileSync(clientPath, JSON.stringify(config));
    process.send({ready: true});
  });
}
