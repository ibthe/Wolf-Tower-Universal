package com.wolftower.app

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Дополнительные движки (zapret tpws, sing-box) кладутся в jniLibs как libtpws.so / libsingbox.so
 * и распаковываются в каталог нативных библиотек, откуда их можно запускать как процессы.
 * Если шаг сборки их не получил, файла нет, и движок в приложении просто не показывается.
 */
object NativeBin {
    const val TPWS = "libtpws.so"
    const val SINGBOX = "libsingbox.so"

    fun file(ctx: Context, name: String): File = File(ctx.applicationInfo.nativeLibraryDir, name)

    fun available(ctx: Context, name: String): Boolean = file(ctx, name).let { it.isFile && it.length() > 0 }
}

/** Внешний процесс с SOCKS5 на localhost: запускает, пишет вывод в лог и ждёт, пока порт откроется. */
class LocalProcess(private val tag: String) {
    private var proc: Process? = null

    fun start(cmd: List<String>, port: Int, onLog: (String) -> Unit, waitMs: Long = 2500): Boolean {
        try {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            proc = p
            thread(isDaemon = true) {
                try {
                    p.inputStream.bufferedReader().forEachLine { onLog("$tag: $it") }
                } catch (_: Exception) {
                }
            }
            val deadline = System.currentTimeMillis() + waitMs
            while (System.currentTimeMillis() < deadline) {
                if (!p.isAlive) {
                    onLog("$tag завершился сразу после запуска (код ${p.exitValue()})")
                    proc = null
                    return false
                }
                try {
                    Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 150) }
                    return true
                } catch (_: Exception) {
                    Thread.sleep(80)
                }
            }
            onLog("$tag не открыл порт $port за ${waitMs / 1000} с")
            stop()
            return false
        } catch (e: Exception) {
            onLog("Ошибка запуска $tag: ${e.message}")
            return false
        }
    }

    fun stop() {
        val p = proc ?: return
        proc = null
        try {
            p.destroy()
            if (!p.waitFor(700, TimeUnit.MILLISECONDS)) {
                p.destroyForcibly()
                p.waitFor(1000, TimeUnit.MILLISECONDS)
            }
        } catch (_: Exception) {
        }
    }
}
