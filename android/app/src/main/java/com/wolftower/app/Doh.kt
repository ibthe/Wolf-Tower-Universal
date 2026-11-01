package com.wolftower.app

import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/** Ответ DoH: IPv4-адреса и наименьший TTL (секунды, 0 = неизвестен). */
data class DohResult(val ips: List<String>, val ttlSec: Int)

/** DoH-запрос A-записей по IP-адресу резолвера (сертификат содержит IP), мимо DNS оператора. */
object Doh {
    private val ENDPOINTS = listOf(
        "https://1.1.1.1/dns-query?name=%s&type=A",
        "https://8.8.8.8/resolve?name=%s&type=A",
    )
    private val HOST_OK = Regex("^[A-Za-z0-9._-]{1,253}$")
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val STATUS_OK = Regex("\"Status\"\\s*:\\s*0")
    private val OBJ = Regex("\\{[^{}]*\\}")
    private val TYPE_A = Regex("\"type\"\\s*:\\s*1\\b")
    private val DATA = Regex("\"data\"\\s*:\\s*\"([^\"]+)\"")
    private val TTL = Regex("\"TTL\"\\s*:\\s*(\\d+)")

    private val pool = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    /** Разбор ответа DoH в формате JSON (Cloudflare и Google). Записи типа A из блока Answer. */
    fun parse(body: String): DohResult? {
        if (!STATUS_OK.containsMatchIn(body)) return null
        val start = body.indexOf("\"Answer\"")
        if (start < 0) return null
        val ips = ArrayList<String>()
        var ttl = Int.MAX_VALUE
        for (m in OBJ.findAll(body, start)) {
            val o = m.value
            if (!TYPE_A.containsMatchIn(o)) continue
            val ip = DATA.find(o)?.groupValues?.get(1) ?: continue
            if (!IPV4.matches(ip)) continue
            ips.add(ip)
            TTL.find(o)?.groupValues?.get(1)?.toIntOrNull()?.let { ttl = minOf(ttl, it) }
        }
        if (ips.isEmpty()) return null
        return DohResult(ips.distinct(), if (ttl == Int.MAX_VALUE) 0 else ttl)
    }

    private fun query(template: String, host: String, timeoutMs: Int): DohResult? {
        var c: HttpsURLConnection? = null
        return try {
            c = java.net.URI(String.format(template, host)).toURL().openConnection() as HttpsURLConnection
            c.connectTimeout = timeoutMs
            c.readTimeout = timeoutMs
            c.setRequestProperty("accept", "application/dns-json")
            if (c.responseCode != 200) return null
            parse(c.inputStream.bufferedReader().use { it.readText() })
        } catch (_: Exception) {
            null
        } finally {
            try {
                c?.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Адреса от всех DoH-серверов сразу. Возвращаем, когда пришёл первый ответ, плюс короткая пауза на остальные:
     * разные серверы отдают разные адреса, а часть адресов оператор блокирует по IP (у Instagram один адрес закрыт,
     * другой открывается). Вызывать из фонового потока.
     */
    fun resolve(host: String, timeoutMs: Int = 3000, graceMs: Long = 250): DohResult? {
        if (!HOST_OK.matches(host)) return null
        val cs = ExecutorCompletionService<DohResult?>(pool)
        for (t in ENDPOINTS) cs.submit(Callable<DohResult?> { query(t, host, timeoutMs) })
        val ips = LinkedHashSet<String>()
        var ttl = Int.MAX_VALUE
        var got = false
        var left = ENDPOINTS.size
        var deadline = System.currentTimeMillis() + timeoutMs + 500L
        while (left > 0) {
            val wait = deadline - System.currentTimeMillis()
            if (wait <= 0) break
            val f = cs.poll(wait, TimeUnit.MILLISECONDS) ?: break
            left--
            val r = try {
                f.get()
            } catch (_: Exception) {
                null
            }
            if (r != null) {
                ips.addAll(r.ips)
                if (r.ttlSec > 0) ttl = minOf(ttl, r.ttlSec)
                if (!got) {
                    got = true
                    deadline = minOf(deadline, System.currentTimeMillis() + graceMs)
                }
            }
        }
        if (ips.isEmpty()) return null
        return DohResult(ips.toList(), if (ttl == Int.MAX_VALUE) 0 else ttl)
    }
}
