const { measureHost } = require('./probe');
const { DohSocks } = require('./dohsocks');

async function runWithLimit(tasks, limit) {
  let i = 0;
  const worker = async () => {
    while (i < tasks.length) {
      const t = tasks[i++];
      await t();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
}

/**
 * Для каждого варианта стратегии поднимается отдельный ByeDPI (по 4 одновременно) и через него
 * проверяются тестовые адреса выбранных сервисов. Возвращает { idСервиса: { стратегия: числоУспехов } }.
 * Проверка идёт через тот же DNS-переходник, что и рабочий режим: иначе системный DNS отдаёт закрытые провайдером
 * адреса (так у Instagram), и ни одна стратегия не проходит, хотя в рабочем режиме страница бы открылась.
 */
async function score({ makeProcess, freePort, forName, profiles, candidates, isCancelled, onProgress, batch = 4, makeFront, stats = {} }) {
  const newFront = makeFront || ((upstreamPort) => new DohSocks({ upstreamPort, staggerMs: 1000 }));
  const counts = {};
  for (const p of profiles) {
    counts[p.id] = {};
    stats[p.id] = {}; // стратегия -> { ok, latencySum, kbpsSum }: по ним среди рабочих путей выбирается самый быстрый
  }

  for (let i = 0; i < candidates.length; i += batch) {
    if (isCancelled()) break;
    const group = candidates.slice(i, i + batch);
    const procs = [];
    try {
      let reason = '';
      for (const strategy of group) {
        const port = await freePort();
        const proc = makeProcess();
        if (await proc.start(port, forName(strategy))) {
          const front = newFront(port);
          await front.start();
          procs.push({ strategy, port: front.port, proc, front });
        } else reason = proc.lastError || reason;
      }
      if (!procs.length) throw new Error('не удалось запустить ByeDPI' + (reason ? ': ' + reason : ''));
      const tasks = [];
      for (const { strategy, port } of procs) {
        for (const profile of profiles) {
          for (const host of profile.probeHosts) {
            tasks.push(async () => {
              const r = await measureHost(host, port, 5000, { minBytes: profile.probeMinBytes, budgetMs: profile.probeBudgetMs });
              if (r.ok) {
                counts[profile.id][strategy] = (counts[profile.id][strategy] || 0) + 1;
                const st = (stats[profile.id][strategy] = stats[profile.id][strategy] || { ok: 0, latencySum: 0, kbpsSum: 0 });
                st.ok++;
                st.latencySum += r.latencyMs;
                st.kbpsSum += r.kbps;
              }
            });
          }
        }
      }
      await runWithLimit(tasks, 12);
    } finally {
      await Promise.all(procs.map((p) => Promise.all([p.front.stop().catch(() => {}), p.proc.stop()])));
    }
    onProgress(Math.min(i + batch, candidates.length));
    // Когда у каждого сервиса есть вариант с полным баллом, дальше не ищем: быстрее и меньше трафика. Но сравниваются
    // минимум две пачки (до 8 вариантов), чтобы из рабочих путей выбрать самый быстрый.
    if (
      i + batch >= 2 * batch &&
      profiles.every((p) => !p.probeHosts.length || Object.values(counts[p.id]).some((c) => c >= p.probeHosts.length))
    ) {
      break;
    }
  }
  return counts;
}

/** Максимум успехов; при равенстве выигрывает более ранний вариант ("none" проверяется первым). */
function chooseBest(counts, candidates) {
  let best = null;
  let bestOk = 0;
  for (const s of candidates) {
    const c = counts[s] || 0;
    if (c > bestOk) {
      best = s;
      bestOk = c;
    }
  }
  return { best, ok: bestOk };
}

/**
 * Качество пути: скорость (КБ/с), уменьшенная на задержку. Больше скорость и меньше задержка = лучше;
 * задержка 500 мс вдвое снижает оценку.
 */
function quality(kbps, latencyMs) {
  return kbps / (1 + latencyMs / 500);
}

/**
 * Все варианты хотя бы с одним успехом, лучший первым: по числу успехов, затем по качеству, затем по порядку в списке
 * стратегий. Возвращает [{ strategy, ok, total, latencyMs, kbps }]. По умолчанию берётся первый, остальные можно
 * выбрать вручную.
 */
function rank(stats, candidates, total) {
  const out = [];
  candidates.forEach((strategy, index) => {
    const st = stats && stats[strategy];
    if (!st || st.ok <= 0) return;
    out.push({
      index,
      strategy,
      ok: st.ok,
      total,
      latencyMs: Math.round(st.latencySum / st.ok),
      kbps: Math.round(st.kbpsSum / st.ok),
    });
  });
  out.sort((a, b) => b.ok - a.ok || quality(b.kbps, b.latencyMs) - quality(a.kbps, a.latencyMs) || a.index - b.index);
  return out.map(({ index, ...rest }) => rest);
}

module.exports = { score, chooseBest, rank, quality };
