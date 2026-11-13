// Дымовая проверка на реальной ОС (Windows/macOS в GitHub Actions): запуск ciadpi, SOCKS5, HTTPS через него, системный прокси.
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const { ByeDpi, binaryPath, freePort } = require('../src/engine');
const sysproxy = require('../src/sysproxy');
const { BASE, forName } = require('../src/profiles');

const out = [];
const log = (m) => { const l = `[${process.platform}] ${m}`; console.log(l); out.push(l); };
let failed = 0;
const step = async (name, fn) => {
  try { const r = await fn(); log(`OK   ${name}${r ? ': ' + r : ''}`); }
  catch (e) { failed++; log(`FAIL ${name}: ${e.message}`); }
};

function socksHttps(port, host, ms = 10000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const t = setTimeout(() => { s.destroy(); reject(new Error('таймаут')); }, ms);
    const fail = (e) => { clearTimeout(t); s.destroy(); reject(e); };
    s.once('error', fail);
    s.once('data', (d) => {
      if (d[0] !== 5 || d[1] !== 0) return fail(new Error('SOCKS5 отказ'));
      const h = Buffer.from(host);
      s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([1, 187])]));
      s.once('data', (r) => {
        if (r[1] !== 0) return fail(new Error('connect код ' + r[1]));
        const c = tls.connect({ socket: s, servername: host }, () => c.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
        let head = '';
        c.on('data', (b) => { if (!head) { head = b.toString('latin1', 0, 15); clearTimeout(t); c.destroy(); resolve(head.split('\r')[0]); } });
        c.on('error', fail);
      });
    });
    s.write(Buffer.from([5, 1, 0]));
  });
}

(async () => {
  const resources = path.join(__dirname, '..', 'resources');
  const bin = binaryPath(resources);
  await step('ciadpi на месте', async () => `${bin} (${fs.statSync(bin).size} байт)`);
  const bye = new ByeDpi(bin);
  bye.on('log', (l) => log('ciadpi: ' + l));
  const port = await freePort();
  let up = false;
  await step('ciadpi запускается и открывает порт', async () => {
    up = await bye.start(port, [...BASE, '--hosts', ':youtube.com', ...forName('split+disorder')]);
    if (!up) throw new Error(bye.lastError || 'не запустился');
  });
  if (up) await step('SOCKS5 + HTTPS до www.youtube.com через ciadpi', () => socksHttps(port, 'www.youtube.com'));
  await bye.stop();

  const store = { d: {}, get(k, def) { return k in this.d ? this.d[k] : def; }, set(k, v) { this.d[k] = v; }, delete(k) { delete this.d[k]; } };
  if (process.platform === 'win32') {
    const url = 'http://127.0.0.1:9/proxy.pac';
    await step('Windows: PAC в реестр и обратно', async () => {
      await sysproxy.install(url, store, log);
      const c = await sysproxy.check(url);
      if (!c.ok) throw new Error('не применилось: ' + c.detail);
      await sysproxy.restore(store, log);
    });
  } else if (process.platform === 'darwin') {
    await step('macOS: список сетевых служб', async () => (await sysproxy.run('networksetup', ['-listallnetworkservices'])).stdout.replace(/\n/g, ' | '));
    await step('macOS: ciadpi подписан/запускается без карантина', async () => (await sysproxy.run('codesign', ['-dv', bin]).catch((e) => ({ stdout: e.stderr }))).stdout.slice(0, 200));
  }
  fs.writeFileSync(path.join(__dirname, '..', 'smoke-log.txt'), out.join('\n') + '\n');
  process.exit(failed ? 1 : 0);
})();
