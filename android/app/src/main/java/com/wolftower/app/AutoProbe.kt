package com.wolftower.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.Future
import kotlin.concurrent.thread

data class ProbeState(
    val running: Boolean = false,
    val done: Boolean = false,
    val progress: String = "",
    val report: String = "",
    /** id сервиса -> "успешно/всего" для выбранной стратегии */
    val scores: Map<String, String> = emptyMap(),
)

/**
 * Автоподбор: для каждого варианта стратегии поднимается отдельный ByeDPI на своём порту (по 4 одновременно),
 * через него проверяются тестовые адреса каждого выбранного сервиса. Все рабочие пути сохраняются списком
 * (лучший первым), а по умолчанию берётся лучший: сначала по числу открывшихся адресов, затем по качеству
 * (скорость, уменьшенная на задержку). Остальные найденные пути можно выбрать вручную. "none" проверяется первым:
 * если без обхода всё открывается, обход не нужен.
 *
 * Проверка идёт через тот же DNS-переходник (DoH), что и рабочий режим: иначе ByeDPI берёт адреса из DNS оператора,
 * и сервис, у которого часть адресов закрыта (Instagram), ложно кажется недоступным при любой стратегии.
 */
/** Накопленные результаты проб одной стратегии для одного сервиса. */
class ProbeStat {
    var ok = 0
    var latencySum = 0L
    var kbpsSum = 0L
}

object AutoProbe {
    val state = MutableStateFlow(ProbeState())

    /**
     * Качество пути: скорость (КБ/с), уменьшенная на задержку. Больше скорость и меньше задержка = лучше.
     * Задержка 500 мс вдвое снижает оценку.
     */
    fun quality(kbps: Int, latencyMs: Int): Double = kbps / (1.0 + latencyMs / 500.0)

    /**
     * Все варианты с хотя бы одним успехом, лучший первым: по числу успехов, затем по качеству, затем по порядку
     * в списке стратегий. Для match_all-сервиса (WhatsApp) "none" не берём: сайт может открываться, а чат нет.
     */
    fun rank(profile: Profile, stats: Map<String, ProbeStat>, candidates: List<String>): List<Settings.RankEntry> {
        val total = profile.probeHosts.size
        val out = ArrayList<Pair<Int, Settings.RankEntry>>()
        candidates.forEachIndexed { index, s ->
            if (s == "none" && profile.matchAll) return@forEachIndexed
            val st = stats[s] ?: return@forEachIndexed
            if (st.ok <= 0) return@forEachIndexed
            out.add(index to Settings.RankEntry(s, st.ok, total, (st.latencySum / st.ok).toInt(), (st.kbpsSum / st.ok).toInt()))
        }
        return out.sortedWith(
            compareByDescending<Pair<Int, Settings.RankEntry>> { it.second.ok }
                .thenByDescending { quality(it.second.kbps, it.second.latencyMs) }
                .thenBy { it.first }
        ).map { it.second }
    }

    @Volatile
    private var cancelled = false
    private const val BATCH = 4

    fun cancel() {
        cancelled = true
    }

    fun start(appCtx: Context, profiles: List<Profile>, strategies: List<String>) {
        if (state.value.running) return
        cancelled = false
        state.value = ProbeState(running = true, progress = tr("Подготовка…"))
        thread(isDaemon = true) {
            try {
                run(appCtx, profiles, strategies)
            } catch (t: Throwable) {
                state.value = ProbeState(done = true, report = trf("Ошибка подбора: {0}", t.message))
            }
        }
    }

    /**
     * Считает, сколько тестовых адресов каждого сервиса открылось при каждой стратегии.
     * Возвращает: id сервиса -> стратегия -> число успехов. Используется и интерфейсом, и самопроверкой.
     */
    fun score(
        ctx: Context,
        profiles: List<Profile>,
        candidates: List<String>,
        isCancelled: () -> Boolean,
        onProgress: (Int) -> Unit,
    ): Map<String, Map<String, Int>> =
        scoreDetailed(ctx, profiles, candidates, isCancelled, onProgress)
            .mapValues { (_, m) -> m.mapValues { it.value.ok } }

    /** То же, что [score], но с задержкой и скоростью по каждому пути. */
    fun scoreDetailed(
        ctx: Context,
        profiles: List<Profile>,
        candidates: List<String>,
        isCancelled: () -> Boolean,
        onProgress: (Int) -> Unit,
    ): Map<String, Map<String, ProbeStat>> {
        val okCounts = HashMap<String, HashMap<String, ProbeStat>>()
        profiles.forEach { okCounts[it.id] = HashMap() }
        var checked = 0

        for (batch in candidates.chunked(BATCH)) {
            if (isCancelled()) break
            val procs = ArrayList<Pair<String, ByeDpiProcess>>()
            val shims = ArrayList<DohSocksShim>()
            val ports = HashMap<String, Int>()
            try {
                batch.forEach { strategy ->
                    val port = Ports.free()
                    val proc = ByeDpiProcess(ctx)
                    if (proc.start(port, StrategyArgs.BASE + StrategyArgs.forName(strategy)) { }) {
                        // Проба идёт через DNS-переходник, как рабочий режим (адреса через DoH, запасные адреса)
                        val shimPort = Ports.free()
                        val shim = DohSocksShim(shimPort, port, { }, staggerMs = 1000)
                        if (shim.start()) {
                            shims.add(shim)
                            procs.add(strategy to proc)
                            ports[strategy] = shimPort
                        } else {
                            proc.stop()
                        }
                    }
                }
                if (procs.isEmpty()) throw IllegalStateException(tr("не удалось запустить ByeDPI"))
                ports.values.forEach { waitPort(it) }

                val pool = Executors.newFixedThreadPool(12)
                try {
                    val jobs = ArrayList<Triple<String, String, Future<ProbeResult>>>()
                    for ((strategy, _) in procs) {
                        for (profile in profiles) {
                            for (host in profile.probeHosts) {
                                val port = ports.getValue(strategy)
                                jobs.add(
                                    Triple(
                                        strategy,
                                        profile.id,
                                        pool.submit(
                                            Callable {
                                                Prober.measure(
                                                    host, port,
                                                    minBytes = profile.probeMinBytes,
                                                    budgetMs = profile.probeBudgetMs,
                                                )
                                            }
                                        ),
                                    )
                                )
                            }
                        }
                    }
                    for ((strategy, profileId, future) in jobs) {
                        val result = try {
                            future.get()
                        } catch (e: InterruptedException) {
                            throw e
                        } catch (_: Exception) {
                            ProbeResult(false)
                        }
                        if (result.ok) {
                            val st = okCounts.getValue(profileId).getOrPut(strategy) { ProbeStat() }
                            st.ok++
                            st.latencySum += result.latencyMs
                            st.kbpsSum += result.kbps
                        }
                    }
                } finally {
                    pool.shutdownNow()
                }
            } finally {
                shims.forEach { runCatching { it.stop() } }
                procs.forEach { it.second.stop() }
            }
            checked += batch.size
            onProgress(checked)
            // Когда у каждого сервиса есть вариант с полным баллом, дальше не ищем: быстрее и меньше трафика.
            // Но сравниваются минимум две пачки (до 8 вариантов), чтобы из рабочих путей выбрать самый быстрый.
            val settled = profiles.all { p ->
                p.probeHosts.isEmpty() || okCounts.getValue(p.id).values.any { it.ok >= p.probeHosts.size }
            }
            if (settled && checked >= 2 * BATCH) break
        }
        return okCounts
    }

    private fun run(ctx: Context, profiles: List<Profile>, strategies: List<String>) {
        val candidates = listOf("none") + strategies
        val stats = scoreDetailed(ctx, profiles, candidates, { cancelled }) { n ->
            state.value = state.value.copy(progress = trf("Проверено вариантов: {0} из {1}", n, candidates.size))
        }

        if (cancelled) {
            state.value = ProbeState(done = true, report = tr("Подбор отменён, настройки не менялись"))
            return
        }

        val lines = ArrayList<String>()
        val scores = HashMap<String, String>()
        for (profile in profiles) {
            val total = profile.probeHosts.size
            if (total == 0) {
                lines.add(trf("{0}: нет адресов для проверки", profile.name))
                continue
            }
            val ranking = rank(profile, stats.getValue(profile.id), candidates)
            val best = ranking.firstOrNull()
            if (best == null) {
                Settings.setRankingFor(ctx, profile.id, emptyList())
                state.value = state.value.copy(progress = trf("Диагностика: {0}…", profile.name))
                val host = profile.probeHosts.first()
                lines.add(trf("{0}: ничего не сработало (0/{1}).\n   Диагностика {2}: {3}", profile.name, total, host, Diagnose.verdict(host)))
            } else {
                // Для match_all-сервиса "без обхода" в ранжирование не попадает (см. rank), поэтому лучший путь всегда с обходом
                Settings.setStrategyFor(ctx, profile.id, best.strategy)
                Settings.setRankingFor(ctx, profile.id, ranking)
                scores[profile.id] = "${best.ok}/$total"
                val label = if (best.strategy == "none") tr("обход не нужен") else best.strategy
                lines.add(
                    trf(
                        "{0}: {1} ({2}/{3}, {4} мс, {5} КБ/с), найдено путей: {6}",
                        profile.name, label, best.ok, total, best.latencyMs, best.kbps, ranking.size,
                    )
                )
            }
        }
        state.value = ProbeState(done = true, report = lines.joinToString("\n"), scores = scores)
    }

    private fun waitPort(port: Int) {
        val end = System.currentTimeMillis() + 2000
        while (System.currentTimeMillis() < end) {
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
                return
            } catch (_: Exception) {
                Thread.sleep(100)
            }
        }
    }
}
