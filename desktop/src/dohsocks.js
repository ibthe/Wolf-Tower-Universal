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

/**
 * Адреса от всех DoH-серверов сразу (параллельно). Возвращаем, как только пришёл первый ответ, плюс короткая пауза
 * на остальные: разные серверы отдают разные адреса, а часть адресов провайдер может блокировать по IP
 * (например, у Instagram один адрес закрыт, а другой открывается).
 */
function dohResolve(name, timeoutMs = 3000, graceMs = 250) {
  return new Promise((resolve, reject) => {
    let left = DOH_ENDPOINTS.length;
    let lastErr;
    const ips = [];
    let ttl = Infinity;
    let timer = null;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ips: [...new Set(ips)], ttl: Number.isFinite(ttl) ? ttl : 0 });
    };
    for (const ep of DOH_ENDPOINTS) {
      dohQuery(ep, name, timeoutMs).then(
        (r) => {
          ips.push(...r.ips);
          ttl = Math.min(ttl, r.ttl);
          if (!timer) timer = setTimeout(finish, graceMs);
          if (--left === 0) finish();
        },
        (e) => {
          lastErr = e;
          if (--left === 0) (ips.length ? finish() : reject(lastErr));
        }
      );
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
async function connectViaUpstream(upstreamPort, ip, port, timeoutMs = 8000, track = () => {}) {
  const up = net.connect({ host: '127.0.0.1', port: upstreamPort });
  track(up);
  up.on('error', () => {});
  up.setTimeout(timeoutMs, () => up.destroy(new Error('таймаут подключения')));
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

/**
 * Серверы Meta принимают любое своё имя на любом своём адресе, а провайдер блокирует адреса по отдельности:
 * www.instagram.com может получить закрытый адрес, а i.instagram.com открытый. Для таких доменов добавляем в список
 * адреса соседних хостов и запоминаем адрес, на котором соединение прошло.
 */
const FAMILIES = [
  {
    key: 'meta',
    // Веб-хосты WhatsApp (сайт, статика, картинки) обслуживаются теми же серверами. Чат (g.whatsapp.net и т. п.)
    // говорит не по HTTPS, ему подходит только свой адрес, поэтому whatsapp.net целиком сюда не входит.
    suffixes: [
      'instagram.com', 'cdninstagram.com', 'instagr.am', 'ig.me', 'facebook.com', 'facebook.net', 'fb.com', 'fbcdn.net', 'fbsbx.com',
      'whatsapp.com', 'wa.me', 'static.whatsapp.net', 'mmg.whatsapp.net', 'pps.whatsapp.net',
    ],
    siblings: ['i.instagram.com', 'graph.instagram.com', 'graph.facebook.com', 'static.xx.fbcdn.net'],
  },
];

function familyOf(host) {
  const h = host.toLowerCase();
  return FAMILIES.find((f) => f.suffixes.some((x) => h === x || h.endsWith('.' + x))) || null;
}

const BAD_MS = 10 * 60 * 1000;
const badUntil = new Map(); // ip -> время, до которого адрес считаем закрытым
const familyGood = new Map(); // семейство -> адрес, на котором соединение прошло

const markBad = (ip) => badUntil.set(ip, Date.now() + BAD_MS);
const markGood = (ip) => badUntil.delete(ip);
const isBad = (ip) => (badUntil.get(ip) || 0) > Date.now();
const byHealth = (ips) => [...ips.filter((i) => !isBad(i)), ...ips.filter(isBad)];

/** Список адресов для попыток: свои, затем рабочий адрес семейства, затем адреса соседних хостов. */
async function candidateIps(host, doh) {
  const fam = familyOf(host);
  let own = [];
  try {
    own = byHealth(await resolve4(host, doh));
  } catch (e) {
    if (!fam) throw e;
  }
  const out = [...own.slice(0, 2)];
  if (fam) {
    const good = familyGood.get(fam.key);
    if (good) out.push(good);
    const sib = await Promise.allSettled(fam.siblings.map((h) => resolve4(h, doh)));
    const extra = byHealth(sib.flatMap((r) => (r.status === 'fulfilled' ? r.value : [])));
    out.push(...extra.slice(0, 3), ...own.slice(2, 3));
  } else {
    out.push(...own.slice(2, 4));
  }
  const list = [...new Set(out)];
  if (!list.length) throw new Error('нет адресов');
  return list.slice(0, 6);
}

/**
 * Пробует адреса по очереди со сдвигом: следующий запускается, если предыдущий не ответил за staggerMs или сразу
 * отказал. Побеждает первый, у кого соединение прошло; остальные закрываются.
 */
function raceConnect(upstreamPort, ips, port, { staggerMs = 1500, timeoutMs = 8000, track = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    let started = 0;
    let finished = 0;
    let done = false;
    let timer = null;
    let lastErr = new Error('нет адресов');
    const socks = new Set();
    const pending = new Set();
    const trackAll = (sock) => {
      socks.add(sock);
      track(sock);
    };
    const next = () => {
      clearTimeout(timer);
      if (done || started >= ips.length) return;
      const ip = ips[started++];
      pending.add(ip);
      if (started < ips.length) timer = setTimeout(next, staggerMs);
      const fail = (e) => {
        pending.delete(ip);
        lastErr = e;
        finished++;
        if (done) return;
        if (started < ips.length) next();
        else if (finished >= ips.length) {
          done = true;
          reject(lastErr);
        }
      };
      connectViaUpstream(upstreamPort, ip, port, timeoutMs, trackAll).then(
        (r) => {
          if (done) return void r.up.destroy();
          if (r.rep !== 0) {
            r.up.destroy();
            return fail(new Error('код ответа ' + r.rep));
          }
          done = true;
          clearTimeout(timer);
          pending.delete(ip);
          for (const other of pending) markBad(other); // не успели ответить, пока другой адрес уже открылся
          for (const s of socks) if (s !== r.up) s.destroy();
          markGood(ip);
          resolve({ ...r, ip });
        },
        fail
      );
    };
    next();
  });
}

const FAIL = (code) => Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]);

class DohSocks {
  /**
   * @param {{upstreamPort: number, log?: Function, doh?: Function}} o
   */
  /**
   * @param {{upstreamPort: number, routes?: {name: string, domains: string[], port: number}[], log?: Function}} o
   * routes: домены, которые идут не в основной ByeDPI, а в отдельный (для сервисов без SNI, например чат WhatsApp).
   */
  constructor({ upstreamPort, routes = [], log = () => {}, doh = dohResolve, staggerMs = 1500, connectTimeoutMs = 8000 }) {
    this.upstreamPort = upstreamPort;
    this.routes = routes;
    this.seen = new Set(); // хосты, о первом соединении с которыми уже записано в журнал
    this.log = log;
    this.doh = doh;
    this.staggerMs = staggerMs;
    this.connectTimeoutMs = connectTimeoutMs;
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

  /**
   * Итог одного соединения для диагностики: "без ответа" (отправили запрос, а в ответ ни байта: обрыв, сброс или
   * блокировка) и "работает". Сообщения по одному хосту не чаще раза в 20 секунд, чтобы не засорять журнал.
   */
  noteDone(host, ip, sent, got, ms) {
    if (!sent && !got) return;
    const bad = got === 0;
    const key = host + (bad ? '!' : '+');
    const last = this.failed.get(key) || 0;
    if (Date.now() - last < 20000) return;
    this.failed.set(key, Date.now());
    this.log(
      bad
        ? `Соединение без ответа: ${host} (${ip}), отправлено ${sent} Б, получено 0 Б, ${ms} мс`
        : `Соединение работает: ${host} (${ip}), получено ${got} Б, ${ms} мс`
    );
  }

  /** Отдельный маршрут для домена (поддомены тоже) или null. */
  routeFor(host) {
    const h = host.toLowerCase();
    return this.routes.find((r) => r.domains.some((d) => h === d || h.endsWith('.' + d))) || null;
  }

  noteFail(host, why, ips) {
    const last = this.failed.get(host) || 0;
    if (Date.now() - last > 30000) {
      this.failed.set(host, Date.now());
      this.log(
        ips
          ? `Не удалось подключиться к ${host} [${ips.join(', ')}] (${why}): адреса, вероятно, закрыты провайдером`
          : `DNS: не удалось определить адрес ${host} (${why})`
      );
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
      ips = await candidateIps(host, this.doh);
    } catch (e) {
      this.noteFail(host, e.message);
      client.write(FAIL(4)); // хост недостижим
      return client.end();
    }

    const route = this.routeFor(host);
    if (!this.seen.has(host) && this.seen.size < 150) {
      this.seen.add(host);
      this.log(`Запрос: ${host}:${port} [${ips.join(', ')}]${route ? ' -> отдельный ByeDPI ' + route.name : ''}`);
    }
    let r;
    try {
      r = await raceConnect(route ? route.port : this.upstreamPort, ips, port, {
        staggerMs: this.staggerMs,
        timeoutMs: this.connectTimeoutMs,
        track: (sock) => {
          this.sockets.add(sock);
          sock.once('close', () => this.sockets.delete(sock));
        },
      });
    } catch (e) {
      this.noteFail(host, e.message, ips);
      client.write(FAIL(5)); // отказ в соединении
      return client.end();
    }
    const fam = familyOf(host);
    if (fam) familyGood.set(fam.key, r.ip);
    if (client.destroyed) return r.up.destroy();
    r.up.on('error', () => client.destroy());
    client.on('close', () => r.up.destroy());
    r.up.on('close', () => client.destroy());
    client.setTimeout(0);
    const t0 = Date.now();
    let sent = 0;
    let got = 0;
    let reported = false;
    const report = () => {
      if (reported) return;
      reported = true;
      this.noteDone(host, r.ip, sent, got, Date.now() - t0);
    };
    client.on('data', (d) => (sent += d.length));
    r.up.on('data', (d) => (got += d.length));
    client.once('close', report);
    r.up.once('close', report);
    client.write(r.reply);
    client.pipe(r.up);
    r.up.pipe(client);
  }
}

module.exports = { DohSocks, resolve4, parseDohAnswer, dohResolve, raceConnect, candidateIps };
