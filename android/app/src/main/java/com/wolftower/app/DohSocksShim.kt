package com.wolftower.app

import java.io.EOFException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** Отдельный ByeDPI для сервиса без SNI (чат WhatsApp идёт по Noise): домены сервиса идут в него, остальное в основной. */
class ShimRoute(val name: String, val domains: List<String>, val port: Int)

/**
 * Промежуточный SOCKS5-прокси между tun2socks и ByeDPI. Принимает от tun2socks запросы с именем домена,
 * определяет адрес через DoH (с запасным системным DNS) и передаёт ByeDPI уже IP-адрес. ByeDPI всё равно
 * видит SNI в TLS, поэтому группы по доменам работают. UDP (в том числе QUIC) не поддерживается и
 * отклоняется: приложения откатываются на TCP.
 *
 * Дополнительно:
 *  - адреса берутся сразу из нескольких DoH-серверов; если первый адрес не отвечает, через [staggerMs] пробуется
 *    следующий (побеждает первый, у кого соединение прошло), закрытые оператором адреса запоминаются;
 *  - серверы Meta принимают любое своё имя на любом своём адресе, поэтому для Instagram, Facebook и веб-хостов
 *    WhatsApp при закрытых адресах берутся адреса соседних хостов (i.instagram.com и т. п.);
 *  - домены из [routes] идут в отдельный ByeDPI без фильтра по SNI (чат WhatsApp);
 *  - в журнал пишутся первые запросы к хосту и итог соединения: работает или без ответа.
 */
class DohSocksShim(
    private val listenPort: Int,
    private val upstreamPort: Int,
    private val onLog: (String) -> Unit,
    private val routes: List<ShimRoute> = emptyList(),
    private val staggerMs: Long = 1500,
    private val connectTimeoutMs: Int = 8000,
    private val firstByteMs: Int = 6000,
    private val resolver: (String) -> DohResult? = { Doh.resolve(it) },
) {
    companion object {
        private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

        // Веб-хосты WhatsApp обслуживаются теми же серверами, что Instagram и Facebook. Чат (g.whatsapp.net и т. п.)
        // говорит не по HTTPS, ему подходит только свой адрес, поэтому whatsapp.net целиком сюда не входит.
        private val META_SUFFIXES = listOf(
            "instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "facebook.com", "facebook.net", "fb.com",
            "fbcdn.net", "fbsbx.com", "whatsapp.com", "wa.me", "static.whatsapp.net", "mmg.whatsapp.net", "pps.whatsapp.net",
            "cdn.whatsapp.net", "crashlogs.whatsapp.net",
        )
        private val META_SIBLINGS = listOf("i.instagram.com", "graph.instagram.com", "graph.facebook.com", "static.xx.fbcdn.net")

        private const val BAD_MS = 10 * 60 * 1000L
        private const val MAX_RACE_MS = 12_000L

        // Состояние общее для всех экземпляров: закрытые адреса остаются закрытыми и для пробы, и для рабочего режима
        private val badUntil = ConcurrentHashMap<String, Long>()

        @Volatile
        private var metaGood: String? = null

        fun isMeta(host: String): Boolean {
            val h = host.lowercase()
            return META_SUFFIXES.any { h == it || h.endsWith(".$it") }
        }

        private fun markBad(ip: String) {
            badUntil[ip] = System.currentTimeMillis() + BAD_MS
        }

        private fun isBad(ip: String): Boolean = (badUntil[ip] ?: 0L) > System.currentTimeMillis()

        private fun byHealth(ips: List<String>): List<String> = ips.filter { !isBad(it) } + ips.filter { isBad(it) }
    }

    @Volatile
    private var server: ServerSocket? = null
    private val pool = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
    private val open = ConcurrentHashMap.newKeySet<Socket>()
    private val cache = ConcurrentHashMap<String, Pair<Long, List<String>>>()
    private val noted = ConcurrentHashMap<String, Long>() // ключ сообщения -> время (чтобы не засорять журнал)
    private val seen = ConcurrentHashMap.newKeySet<String>()

    val port: Int get() = server?.localPort ?: listenPort

    fun start(): Boolean {
        return try {
            val s = ServerSocket()
            s.reuseAddress = true
            s.bind(InetSocketAddress("127.0.0.1", listenPort))
            server = s
            thread(isDaemon = true) {
                while (!s.isClosed) {
                    try {
                        val c = s.accept()
                        pool.execute { handle(c) }
                    } catch (_: Exception) {
                        break
                    }
                }
            }
            true
        } catch (e: Exception) {
            onLog("DoH-прокси не запустился: ${e.message}")
            false
        }
    }

    fun stop() {
        try {
            server?.close()
        } catch (_: Exception) {
        }
        for (s in open) closeQuiet(s)
        open.clear()
        pool.shutdownNow()
    }

    private fun closeQuiet(s: Socket?) {
        try {
            s?.close()
        } catch (_: Exception) {
        }
    }

    private fun track(s: Socket): Socket {
        open.add(s)
        return s
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw EOFException()
            off += n
        }
    }

    private fun reply(out: java.io.OutputStream, code: Int) {
        out.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        out.flush()
    }

    private fun note(key: String, minGapMs: Long, text: String) {
        val now = System.currentTimeMillis()
        val last = noted[key] ?: 0L
        if (now - last < minGapMs) return
        noted[key] = now
        onLog(text)
    }

    // ---------------------------------------------------------------- адреса

    private fun resolve4(host: String): List<String> {
        if (IPV4.matches(host)) return listOf(host)
        val key = host.lowercase()
        val now = System.currentTimeMillis()
        cache[key]?.let { if (it.first > now) return it.second }
        var ips: List<String> = emptyList()
        var ttl = 60
        try {
            val r = resolver(key)
            if (r != null && r.ips.isNotEmpty()) {
                ips = r.ips
                if (r.ttlSec > 0) ttl = r.ttlSec
            }
        } catch (_: Exception) {
        }
        if (ips.isEmpty()) {
            ips = try {
                InetAddress.getAllByName(key).filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }
            } catch (_: Exception) {
                emptyList()
            }
        }
        if (ips.isEmpty()) return emptyList()
        cache[key] = (now + ttl.coerceIn(60, 600) * 1000L) to ips
        return ips
    }

    /** Адреса для попыток: свои, затем рабочий адрес Meta, затем адреса соседних хостов (только для Meta). */
    private fun candidateIps(host: String): List<String> {
        val meta = isMeta(host)
        val own = byHealth(resolve4(host))
        val out = ArrayList<String>()
        out.addAll(own.take(2))
        if (meta) {
            metaGood?.let { out.add(it) }
            val jobs = META_SIBLINGS.map { s -> pool.submit(Callable { resolve4(s) }) }
            val extra = jobs.flatMap {
                try {
                    it.get(4, TimeUnit.SECONDS)
                } catch (_: Exception) {
                    emptyList()
                }
            }.distinct()
            out.addAll(byHealth(extra).take(3))
            out.addAll(own.drop(2).take(1))
        } else {
            out.addAll(own.drop(2).take(2))
        }
        return out.distinct().take(6)
    }

    // ---------------------------------------------------------------- подключение к ByeDPI

    private class Attempt(val ip: String, val sock: Socket?, val code: Int, val err: String?)

    /** Одна попытка: SOCKS5 к ByeDPI с просьбой соединиться с ip:port. */
    private fun attempt(ip: String, portBytes: ByteArray, upPort: Int, race: AtomicBoolean): Attempt {
        val u = track(Socket())
        try {
            u.connect(InetSocketAddress("127.0.0.1", upPort), 5000)
            u.tcpNoDelay = true
            u.soTimeout = connectTimeoutMs
            val uin = u.getInputStream()
            val uout = u.getOutputStream()
            uout.write(byteArrayOf(5, 1, 0))
            uout.flush()
            val g = ByteArray(2)
            readFully(uin, g)
            if (g[1].toInt() != 0) throw EOFException("ByeDPI отказал в SOCKS5")
            val addr = ip.split('.').map { it.toInt().toByte() }.toByteArray()
            uout.write(byteArrayOf(5, 1, 0, 1) + addr + portBytes)
            uout.flush()
            val rh = ByteArray(4)
            readFully(uin, rh)
            val skip = when (rh[3].toInt()) {
                1 -> 4
                4 -> 16
                3 -> uin.read()
                else -> 0
            }
            readFully(uin, ByteArray(skip + 2))
            if (race.get()) { // гонка уже закончилась: этот сокет лишний
                closeQuiet(u)
                return Attempt(ip, null, -1, "поздно")
            }
            return Attempt(ip, u, rh[1].toInt(), null)
        } catch (e: Exception) {
            closeQuiet(u)
            return Attempt(ip, null, -1, e.message ?: e.javaClass.simpleName)
        }
    }

    private class Winner(val ip: String, val sock: Socket)

    /**
     * Пробует адреса по очереди со сдвигом: следующий запускается, если предыдущий не ответил за staggerMs или сразу
     * отказал. Побеждает первый, у кого соединение прошло; остальные закрываются, а не успевшие помечаются закрытыми.
     */
    private fun race(ips: List<String>, portBytes: ByteArray, upPort: Int, errOut: Array<String?>): Winner? {
        val done = AtomicBoolean(false)
        val q = LinkedBlockingQueue<Attempt>()
        val pending = LinkedHashSet<String>()
        var started = 0
        var finished = 0
        fun launch() {
            val ip = ips[started++]
            pending.add(ip)
            try {
                pool.execute { q.offer(attempt(ip, portBytes, upPort, done)) }
            } catch (e: Exception) {
                q.offer(Attempt(ip, null, -1, e.message))
            }
        }
        launch()
        val deadline = System.currentTimeMillis() + minOf(MAX_RACE_MS, connectTimeoutMs + staggerMs * (ips.size - 1))
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) break
            val wait = if (started < ips.size) minOf(staggerMs, remaining) else remaining
            val a = q.poll(wait, TimeUnit.MILLISECONDS)
            if (a == null) {
                if (started < ips.size) launch() else break
                continue
            }
            finished++
            pending.remove(a.ip)
            if (a.sock != null && a.code == 0) {
                done.set(true)
                for (p in pending) markBad(p) // не успели ответить, пока другой адрес уже открылся
                badUntil.remove(a.ip)
                return Winner(a.ip, a.sock)
            }
            errOut[0] = a.err ?: "код ответа ${a.code}"
            closeQuiet(a.sock)
            if (started < ips.size) launch() else if (finished >= ips.size) break
        }
        done.set(true)
        if (errOut[0] == null) errOut[0] = "таймаут подключения"
        return null
    }

    private fun routeFor(host: String): ShimRoute? {
        val h = host.lowercase()
        return routes.firstOrNull { r -> r.domains.any { h == it || h.endsWith(".$it") } }
    }

    private fun noteDone(host: String, ip: String, sent: Long, got: Long, ms: Long) {
        if (sent == 0L && got == 0L) return
        if (got == 0L) {
            note("$host!", 20_000, "Соединение без ответа: $host ($ip), отправлено $sent Б, получено 0 Б, $ms мс")
        } else {
            note("$host+", 20_000, "Соединение работает: $host ($ip), получено $got Б, $ms мс")
        }
    }

    // ---------------------------------------------------------------- обработка клиента

    private fun handle(client: Socket) {
        track(client)
        var up: Socket? = null
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15000
            val cin = client.getInputStream()
            val cout = client.getOutputStream()

            if (cin.read() != 5) return
            val n = cin.read()
            if (n < 0) return
            readFully(cin, ByteArray(n))
            cout.write(byteArrayOf(5, 0))
            cout.flush()

            val hdr = ByteArray(4)
            readFully(cin, hdr)
            if (hdr[0].toInt() != 5) return
            val cmd = hdr[1].toInt()
            val addrType = hdr[3].toInt()
            var host: String? = null
            var rawAddr: ByteArray? = null
            when (addrType) {
                1 -> rawAddr = ByteArray(4).also { readFully(cin, it) }
                4 -> {
                    ByteArray(16).also { readFully(cin, it) }
                    readFully(cin, ByteArray(2))
                    reply(cout, 8) // IPv6 не используем (ByeDPI запущен с -X)
                    return
                }
                3 -> {
                    val len = cin.read()
                    if (len <= 0) return
                    host = String(ByteArray(len).also { readFully(cin, it) }, Charsets.US_ASCII)
                }
                else -> {
                    reply(cout, 8)
                    return
                }
            }
            val portBytes = ByteArray(2)
            readFully(cin, portBytes)
            if (cmd != 1) {
                reply(cout, 7) // UDP ASSOCIATE и остальное не поддерживается
                return
            }
            val port = ((portBytes[0].toInt() and 0xff) shl 8) or (portBytes[1].toInt() and 0xff)
            val name = host ?: rawAddr!!.joinToString(".") { (it.toInt() and 0xff).toString() }

            val ips = candidateIps(name)
            if (ips.isEmpty()) {
                note("dns:$name", 30_000, "DNS: не удалось определить адрес $name")
                reply(cout, 4)
                return
            }
            val route = routeFor(name)
            if (seen.size < 150 && seen.add(name)) {
                onLog("Запрос: $name:$port [${ips.joinToString(", ")}]" + (route?.let { " -> отдельный ByeDPI ${it.name}" } ?: ""))
            }

            val err = arrayOfNulls<String>(1)
            val tRace = System.currentTimeMillis()
            val w = race(ips, portBytes, route?.port ?: upstreamPort, err)
            if (w == null) {
                note(
                    "conn:$name", 30_000,
                    "Не удалось подключиться к $name [${ips.joinToString(", ")}] (${err[0]}): адреса, вероятно, закрыты оператором",
                )
                reply(cout, 5)
                return
            }
            if (isMeta(name)) metaGood = w.ip
            // Долгие соединения (WebSocket чата) попадают в журнал только после закрытия, поэтому успех пишем сразу
            note("$name~", 20_000, "Подключено: $name (${w.ip}), ${System.currentTimeMillis() - tRace} мс")
            var cur: Winner = w
            up = cur.sock
            reply(cout, 0)

            // Если клиент начинает с TLS ClientHello, а сервер за firstByteMs не ответил (оператор пропустил соединение,
            // но режет запрос), адрес считается закрытым: запрос повторяется на следующем адресе, а если адресов больше
            // нет, соединение закрывается сразу, а не через 30 секунд, и приложение быстро переключается само.
            var sent = 0L
            var got = 0L
            val hello = readFirstFlight(client)
            if (hello != null) sent += hello.size
            val isTls = hello != null && hello.size > 2 && hello[0].toInt() == 0x16 && hello[1].toInt() == 0x03
            val route2 = route?.port ?: upstreamPort
            if (hello != null && isTls) {
                val tried = HashSet<String>()
                tried.add(cur.ip)
                var attempt = 0
                while (true) {
                    val ms = if (attempt == 0) firstByteMs else maxOf(2500, firstByteMs - 2000)
                    val first = firstReply(cur.sock, hello, ms)
                    if (first != null) {
                        got += first.size
                        cout.write(first)
                        cout.flush()
                        break
                    }
                    markBad(cur.ip)
                    closeQuiet(cur.sock)
                    val rest = ips.filter { it !in tried }
                    if (attempt >= 2 || rest.isEmpty()) {
                        note("$name#", 20_000, "Сервер не ответил на запрос: $name (${cur.ip}), соединение закрыто")
                        return
                    }
                    val e2 = arrayOfNulls<String>(1)
                    val next = race(rest, portBytes, route2, e2) ?: return
                    tried.add(next.ip)
                    cur = next
                    up = cur.sock
                    note("$name>", 20_000, "Адрес не ответил, повтор на другом: $name (${cur.ip})")
                    attempt++
                }
            } else if (hello != null) {
                cur.sock.getOutputStream().write(hello)
                cur.sock.getOutputStream().flush()
            }

            val u = cur.sock
            client.soTimeout = 0
            u.soTimeout = 0
            val t0 = System.currentTimeMillis()
            val done = CountDownLatch(1)
            var got2 = 0L
            pool.execute {
                got2 = pump(u, client)
                done.countDown()
            }
            val sent2 = pump(client, u)
            done.await(2, TimeUnit.MINUTES)
            noteDone(name, cur.ip, sent + sent2, got + got2, System.currentTimeMillis() - t0)
        } catch (_: Exception) {
        } finally {
            closeQuiet(client)
            closeQuiet(up)
            open.remove(client)
            if (up != null) open.remove(up)
        }
    }


    /** Первая порция данных клиента (для TLS собирается запись целиком). null, если за 3 секунды ничего или клиент закрылся. */
    private fun readFirstFlight(client: Socket): ByteArray? {
        return try {
            client.soTimeout = 3000
            val inp = client.getInputStream()
            val buf = ByteArray(16384)
            var n = inp.read(buf)
            if (n <= 0) return null
            if (buf[0].toInt() == 0x16 && n >= 5) {
                val want = minOf(5 + (((buf[3].toInt() and 0xff) shl 8) or (buf[4].toInt() and 0xff)), buf.size)
                client.soTimeout = 2000 // запись пришла не целиком: ждём остаток недолго
                while (n < want) {
                    val k = inp.read(buf, n, want - n)
                    if (k <= 0) break
                    n += k
                }
            }
            buf.copyOf(n)
        } catch (_: SocketTimeoutException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    /** Отправляет hello и ждёт первый ответ сервера. null, если за ms ничего не пришло или соединение закрылось. */
    private fun firstReply(sock: Socket, hello: ByteArray, ms: Int): ByteArray? {
        return try {
            sock.soTimeout = ms
            val out = sock.getOutputStream()
            out.write(hello)
            out.flush()
            val buf = ByteArray(16384)
            val n = sock.getInputStream().read(buf)
            if (n <= 0) null else buf.copyOf(n)
        } catch (_: Exception) {
            null
        }
    }

    /** Переносит данные и возвращает число перенесённых байт. */
    private fun pump(from: Socket, to: Socket): Long {
        var total = 0L
        try {
            val buf = ByteArray(16384)
            val i = from.getInputStream()
            val o = to.getOutputStream()
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                o.write(buf, 0, n)
                o.flush()
                total += n
            }
        } catch (_: Exception) {
        }
        try {
            to.shutdownOutput()
        } catch (_: Exception) {
        }
        return total
    }
}
