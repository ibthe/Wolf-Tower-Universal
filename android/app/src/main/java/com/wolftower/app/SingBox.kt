package com.wolftower.app

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/** Бесплатный аккаунт Cloudflare WARP (WireGuard) для sing-box. */
data class WarpAccount(
    val privateKey: String,
    val peerPublicKey: String,
    val peerHost: String,
    val peerPort: Int,
    val addressV4: String,
    val addressV6: String,
    val reserved: List<Int>,
) {
    fun toJson(): String = JSONObject()
        .put("private_key", privateKey)
        .put("peer_public_key", peerPublicKey)
        .put("peer_host", peerHost)
        .put("peer_port", peerPort)
        .put("address_v4", addressV4)
        .put("address_v6", addressV6)
        .put("reserved", JSONArray(reserved))
        .toString()

    companion object {
        fun fromJson(text: String?): WarpAccount? {
            if (text.isNullOrBlank()) return null
            return try {
                val o = JSONObject(text)
                val r = o.getJSONArray("reserved")
                WarpAccount(
                    o.getString("private_key"),
                    o.getString("peer_public_key"),
                    o.getString("peer_host"),
                    o.getInt("peer_port"),
                    o.getString("address_v4"),
                    o.optString("address_v6", ""),
                    List(r.length()) { r.getInt(it) },
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}

/** Конфигурации sing-box: локальный SOCKS5 (mixed) на 127.0.0.1, дальше прямой выход с фрагментацией TLS или WARP. */
object SingBoxConfig {
    private fun obj(vararg p: Pair<String, Any?>): JSONObject {
        val o = JSONObject()
        for ((k, v) in p) o.put(k, v)
        return o
    }

    private fun arr(vararg v: Any?): JSONArray {
        val a = JSONArray()
        for (x in v) a.put(x)
        return a
    }

    private fun inbound(port: Int) = obj("type" to "mixed", "tag" to "in", "listen" to "127.0.0.1", "listen_port" to port)

    /** Сервер DNS с тегом "remote": DoH Cloudflare/Google или системный. */
    private fun dnsServer(choice: String, detour: String?): JSONObject {
        val server = when (choice) {
            "google" -> "8.8.8.8"
            "system" -> null
            else -> "1.1.1.1"
        }
        if (server == null) return obj("type" to "local", "tag" to "remote")
        val o = obj("type" to "https", "tag" to "remote", "server" to server)
        if (detour != null) o.put("detour", detour)
        return o
    }

    private fun dns(choice: String, detour: String?) = obj(
        "servers" to arr(dnsServer(choice, detour)),
        "final" to "remote",
        "strategy" to "prefer_ipv4",
    )

    private fun log() = obj("level" to "warn", "timestamp" to false)

    /** Без сервера: имена через DoH, TLS-рукопожатие режется на фрагменты. */
    fun fragment(port: Int, dnsChoice: String): JSONObject = obj(
        "log" to log(),
        "dns" to dns(dnsChoice, null),
        "inbounds" to arr(inbound(port)),
        "outbounds" to arr(obj("type" to "direct", "tag" to "direct")),
        "route" to obj(
            "rules" to arr(
                obj("action" to "route-options", "tls_fragment" to true, "tls_fragment_fallback_delay" to "500ms"),
            ),
            "final" to "direct",
            "default_domain_resolver" to "remote",
        ),
    )

    /** Весь трафик через бесплатный WARP (WireGuard до Cloudflare). */
    fun warp(port: Int, dnsChoice: String, a: WarpAccount): JSONObject {
        val addresses = arr(a.addressV4 + "/32")
        if (a.addressV6.isNotBlank()) addresses.put(a.addressV6 + "/128")
        val peer = obj(
            "address" to a.peerHost,
            "port" to a.peerPort,
            "public_key" to a.peerPublicKey,
            "allowed_ips" to arr("0.0.0.0/0", "::/0"),
            "reserved" to JSONArray(a.reserved),
        )
        val endpoint = obj(
            "type" to "wireguard",
            "tag" to "warp",
            "address" to addresses,
            "private_key" to a.privateKey,
            "mtu" to 1280,
            "peers" to arr(peer),
        )
        return obj(
            "log" to log(),
            "dns" to dns(dnsChoice, if (dnsChoice == "system") null else "warp"),
            "inbounds" to arr(inbound(port)),
            "endpoints" to arr(endpoint),
            "outbounds" to arr(obj("type" to "direct", "tag" to "direct")),
            "route" to obj("final" to "warp", "default_domain_resolver" to "remote"),
        )
    }
}

/** Регистрация анонимного бесплатного аккаунта WARP (тот же API, что у wgcf). Ключи создаёт сам sing-box. */
object Warp {
    private const val API = "https://api.cloudflareclient.com/v0a2483/reg"

    /** null = успех, иначе текст ошибки. Вызывать не из главного потока. */
    fun register(ctx: Context): String? {
        val bin = NativeBin.file(ctx, NativeBin.SINGBOX)
        if (!bin.isFile) return "sing-box не вошёл в эту сборку"
        return try {
            val keys = ProcessBuilder(bin.path, "generate", "wg-keypair").redirectErrorStream(true).start()
            val text = keys.inputStream.bufferedReader().readText()
            keys.waitFor(10, TimeUnit.SECONDS)
            val priv = Regex("PrivateKey:\\s*(\\S+)").find(text)?.groupValues?.get(1)
            val pub = Regex("PublicKey:\\s*(\\S+)").find(text)?.groupValues?.get(1)
            if (priv == null || pub == null) return "Не удалось создать ключи: ${text.take(120)}"

            val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            fmt.timeZone = TimeZone.getTimeZone("UTC")
            val body = JSONObject()
                .put("key", pub)
                .put("install_id", "")
                .put("fcm_token", "")
                .put("tos", fmt.format(Date()))
                .put("type", "Android")
                .put("model", "PC")
                .put("locale", "en_US")
                .toString()
            val conn = URL(API).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 10_000
            conn.readTimeout = 15_000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            conn.setRequestProperty("User-Agent", "okhttp/3.12.1")
            conn.setRequestProperty("CF-Client-Version", "a-6.81-2410012252.0")
            conn.outputStream.use { it.write(body.toByteArray()) }
            val code = conn.responseCode
            val resp = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) return "Cloudflare ответил $code: ${resp.take(120)}"

            val cfg = JSONObject(resp).getJSONObject("config")
            val peer = cfg.getJSONArray("peers").getJSONObject(0)
            val endpoint = peer.getJSONObject("endpoint")
            // Адрес берём числовой, чтобы при запуске не зависеть от DNS оператора
            val hostPort = endpoint.optString("host", "engage.cloudflareclient.com:2408")
            val port = hostPort.substringAfterLast(':', "2408").toIntOrNull() ?: 2408
            val v4 = endpoint.optString("v4", "").substringBeforeLast(':').ifBlank { "162.159.192.1" }
            val addr = cfg.getJSONObject("interface").getJSONObject("addresses")
            val clientId = Base64.decode(cfg.optString("client_id", ""), Base64.DEFAULT)
            val reserved = clientId.take(3).map { it.toInt() and 0xFF }
            val account = WarpAccount(
                privateKey = priv,
                peerPublicKey = peer.getString("public_key"),
                peerHost = v4,
                peerPort = port,
                addressV4 = addr.getString("v4"),
                addressV6 = addr.optString("v6", ""),
                reserved = if (reserved.size == 3) reserved else listOf(0, 0, 0),
            )
            Settings.setWarpAccount(ctx, account.toJson())
            null
        } catch (e: Exception) {
            "Не удалось создать аккаунт WARP: ${e.message}"
        }
    }
}

/** Запуск sing-box: проверка конфигурации (ошибка сразу видна в логе), затем сам процесс. */
object SingBoxRunner {
    fun start(ctx: Context, engine: String, port: Int, proc: LocalProcess, onLog: (String) -> Unit): Boolean {
        val bin = NativeBin.file(ctx, NativeBin.SINGBOX)
        if (!bin.isFile) {
            onLog("sing-box не вошёл в эту сборку")
            return false
        }
        val dns = Settings.sbDns(ctx)
        val cfg = if (engine == Settings.ENGINE_SB_WARP) {
            val acc = WarpAccount.fromJson(Settings.warpAccount(ctx))
            if (acc == null) {
                onLog("Сначала создайте WARP-аккаунт (Дополнительно → Способ обхода)")
                return false
            }
            SingBoxConfig.warp(port, dns, acc)
        } else {
            SingBoxConfig.fragment(port, dns)
        }
        val dir = File(ctx.filesDir, "singbox").apply { mkdirs() }
        val file = File(dir, "config.json")
        file.writeText(cfg.toString(2))
        return try {
            val check = ProcessBuilder(bin.path, "check", "-c", file.path, "-D", dir.path).redirectErrorStream(true).start()
            val out = check.inputStream.bufferedReader().readText()
            val code = check.waitFor()
            if (code != 0) {
                onLog("sing-box: конфигурация отклонена: ${out.trim().take(300)}")
                return false
            }
            onLog(if (engine == Settings.ENGINE_SB_WARP) "sing-box: WARP, DNS=$dns" else "sing-box: TLS-фрагменты, DNS=$dns")
            proc.start(listOf(bin.path, "run", "-c", file.path, "-D", dir.path), port, onLog, 8000)
        } catch (e: Exception) {
            onLog("Ошибка запуска sing-box: ${e.message}")
            false
        }
    }
}
