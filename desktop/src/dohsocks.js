const dns = require('dns');
const https = require('https');
const net = require('net');

/**
 * ByeDPI сам определяет адрес домена через системный DNS (getaddrinfo). Если DNS провайдера режет или подменяет
 * ответ для домена (в журнале: "byedpi: not resolved: studio.youtube.com"), страница не открывается, хотя сам обход
 * работает. Этот модуль стоит перед ByeDPI: принимает SOCKS5 от браузера, сам определяет IPv4 через DNS-over-HTTPS
 * (серверы адресуются по IP, без SNI, поэтому по имени их не заблокировать), а ByeDPI отдаёт уже готовый адрес.
 * Подбор группы стратегии в ByeDPI идёт по SNI, поэтому от адреса вместо имени ничего не меняется.
 */

// JSON-API DoH: у обоих серверов в сертификате есть IP-адрес, поэтому подключение идёт по IP.
const DOH_ENDPOINTS = [
  { host: '1.1.1.1', path: '/dns-query' },
  { host: '8.8.8.8', path: '/resolve' },
];

const agent = new https.Agent({ keepAlive: true, maxSockets: 8 });
const cache = new Map(); // host -> { ips, exp }
const MIN_TTL = 60;
const MAX_TTL = 600;

/** Достаёт IPv4-адреса (запись типа A) и TTL из ответа DoH в формате JSON. */
function parseDohAnswer(json) {
  if (!json || json.Status !== 0 || !Array.isArray(json.Answer)) return { ips: [], ttl: 0 };
  const a = json.Answer.filter((r) => r && r.type === 1 && net.isIPv4(String(r.data)));
  return {
    ips: a.map((r) => String(r.data)),
    ttl: a.length ? Math.min(...a.map((r) => Number(r.TTL) || 0)) : 0,
  };
}

function dohQuery(ep, name, timeoutMs) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: ep.host,
      port: ep.port || 443,
      path: `${ep.path}?name=${encodeURIComponent(name)}&type=A`,
      method: 'GET',
      headers: { Accept: 'application/dns-json' },
      agent,
      timeout: timeoutMs,
    };
    const req = https.request(opts, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + res.statusCode));
      }
      const parts = [];
      res.on('data', (d) => parts.push(d));
      res.on('end', () => {
        try {
          const r = parseDohAnswer(JSON.parse(Buffer.concat(parts).toString('utf8')));
          r.ips.length ? resolve(r) : reject(new Error('нет записей A'));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('таймаут')));
    req.on('error', reject);
    req.end();
  });
}

/** Первый успешный ответ из всех DoH-серверов (параллельно). */
function dohResolve(name, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    let left = DOH_ENDPOINTS.length;
    let lastErr;
    for (const ep of DOH_ENDPOINTS) {
      dohQuery(ep, name, timeoutMs).then(resolve, (e) => {
        lastErr = e;
        if (--left === 0) reject(lastErr);
      });
    }
  });
}

/**
 * IPv4-адреса домена: сначала DoH, при недоступности DoH системный DNS. Результат кэшируется.
 * @param {(name: string) => Promise<{ips: string[], ttl: number}>} [doh] подмена для тестов
 */
async function resolve4(host, doh = dohResolve) {
  if (net.isIPv4(host)) return [host];
  const key = host.toLowerCase();
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return hit.ips;
  let res = null;
  try {
    res = await doh(key);
  } catch (_) {
    /* DoH недоступен: пробуем системный DNS */
  }
  if (!res || !res.ips.length) {
    const list = await dns.promises.lookup(key, { family: 4, all: true });
    res = { ips: list.map((x) => x.address), ttl: MIN_TTL };
  }
  const ttl = Math.max(MIN_TTL, Math.min(MAX_TTL, res.ttl || MIN_TTL));
  cache.set(key, { ips: res.ips, exp: Date.now() + ttl * 1000 });
  return res.ips;
}

/** Читает из сокета ровно n байт (остаток остаётся в сокете). */
function readExact(sock, n) {
  return new Promise((resolve, reject) => {
    const tryRead = () => {
      const chunk = sock.read(n);
      if (chunk) return cleanup(), resolve(chunk);
    };
    const onErr = (e) => (cleanup(), reject(e || new Error('закрыто')));
    const onEnd = () => onErr(new Error('соединение закрыто'));
    const cleanup = () => {
      sock.off('readable', tryRead);
      sock.off('error', onErr);
      sock.off('close', onEnd);
      sock.off('end', onEnd);
    };
    sock.on('readable', tryRead);
    sock.once('error', onErr);
    sock.once('close', onEnd);
    sock.once('end', onEnd);
    tryRead();
  });
}

/** Подключается к ByeDPI по SOCKS5 и просит соединение с IPv4:портом. Возвращает сокет и ответ ByeDPI. */
async function connectViaUpstream(upstreamPort, ip, port) {
  const up = net.connect({ host: '127.0.0.1', port: upstreamPort });
  up.setTimeout(15000, () => up.destroy(new Error('таймаут подключения')));
  await new Promise((res, rej) => {
    up.once('connect', res);
    up.once('error', rej);
  });
  up.write(Buffer.from([5, 1, 0]));
  const hello = await readExact(up, 2);
  if (hello[0] !== 5 || hello[1] !== 0) throw new Error('ByeDPI отказал в SOCKS5');
  const req = Buffer.alloc(10);
  req.set([5, 1, 0, 1], 0);
  ip.split('.').forEach((o, i) => (req[4 + i] = Number(o)));
  req.writeUInt16BE(port, 8);
  up.write(req);
  const head = await readExact(up, 4);
  const rest = head[3] === 1 ? 6 : head[3] === 4 ? 18 : 0;
  const tail = rest ? await readExact(up, rest) : Buffer.alloc(0);
  up.setTimeout(0);
  return { up, rep: head[1], reply: Buffer.concat([head, tail]) };
}

const FAIL = (code) => Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]);

class DohSocks {
  /**
   * @param {{upstreamPort: number, log?: Function, doh?: Function}} o
   */
  constructor({ upstreamPort, log = () => {}, doh = dohResolve }) {
    this.upstreamPort = upstreamPort;
    this.log = log;
    this.doh = doh;
    this.server = null;
    this.port = 0;
    this.sockets = new Set();
    this.failed = new Map(); // домен -> время последнего сообщения об ошибке (чтобы не засорять журнал)
  }

  async start() {
    this.server = net.createServer((c) => this.handle(c).catch(() => c.destroy()));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', resolve);
    });
    this.port = this.server.address().port;
  }

  async stop() {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    if (this.server) await new Promise((r) => this.server.close(r));
    this.server = null;
  }

  noteFail(host, why) {
    const last = this.failed.get(host) || 0;
    if (Date.now() - last > 30000) {
      this.failed.set(host, Date.now());
      this.log(`DNS: не удалось определить адрес ${host} (${why})`);
    }
  }

  async handle(client) {
    this.sockets.add(client);
    client.once('close', () => this.sockets.delete(client));
    client.on('error', () => {});
    client.setTimeout(20000, () => client.destroy());

    const g = await readExact(client, 2);
    if (g[0] !== 5) return client.destroy();
    await readExact(client, g[1]); // список методов, поддерживаем только "без пароля"
    client.write(Buffer.from([5, 0]));

    const h = await readExact(client, 4);
    if (h[0] !== 5 || h[1] !== 1) {
      client.write(FAIL(7)); // команда не поддерживается (UDP и т. п.)
      return client.end();
    }
    let host;
    if (h[3] === 1) host = [...(await readExact(client, 4))].join('.');
    else if (h[3] === 3) {
      const len = (await readExact(client, 1))[0];
      host = (await readExact(client, len)).toString('latin1');
    } else {
      client.write(FAIL(8)); // IPv6 не используем (ByeDPI запущен с -X)
      return client.end();
    }
    const port = (await readExact(client, 2)).readUInt16BE(0);

    let ips;
    try {
      ips = await resolve4(host, this.doh);
    } catch (e) {
      this.noteFail(host, e.message);
      client.write(FAIL(4)); // хост недостижим
      return client.end();
    }

    let last = null;
    for (const ip of ips.slice(0, 3)) {
      let r;
      try {
        r = await connectViaUpstream(this.upstreamPort, ip, port);
      } catch (e) {
        last = e;
        continue;
      }
      if (r.rep !== 0) {
        r.up.destroy();
        last = new Error('код ответа ' + r.rep);
        continue;
      }
      this.sockets.add(r.up);
      r.up.once('close', () => this.sockets.delete(r.up));
      r.up.on('error', () => client.destroy());
      client.on('close', () => r.up.destroy());
      r.up.on('close', () => client.destroy());
      client.setTimeout(0);
      client.write(r.reply);
      client.pipe(r.up);
      r.up.pipe(client);
      return;
    }
    this.noteFail(host, last ? last.message : 'нет адресов');
    client.write(FAIL(5)); // отказ в соединении
    client.end();
  }
}

module.exports = { DohSocks, resolve4, parseDohAnswer, dohResolve };
