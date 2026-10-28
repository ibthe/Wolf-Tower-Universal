package com.wolftower.app

/**
 * Стратегии zapret tpws (режим --socks, без root). Используются только флаги, которые есть во всех
 * версиях tpws. --split-any-protocol нужен, чтобы резать и трафик без TLS/HTTP (чат WhatsApp, Noise).
 */
object TpwsArgs {
    const val DEFAULT = "split1+disorder"

    private val lib = linkedMapOf(
        "split1+disorder" to listOf("--split-any-protocol", "--split-pos=1", "--disorder"),
        "split1" to listOf("--split-any-protocol", "--split-pos=1"),
        "split2+disorder" to listOf("--split-any-protocol", "--split-pos=2", "--disorder"),
        "split3" to listOf("--split-any-protocol", "--split-pos=3"),
        "split1+oob" to listOf("--split-any-protocol", "--split-pos=1", "--oob"),
        "split2+oob+disorder" to listOf("--split-any-protocol", "--split-pos=2", "--oob", "--disorder"),
    )

    val names: List<String> get() = lib.keys.toList()

    fun forName(name: String): List<String> = lib[name] ?: lib.getValue(DEFAULT)
}
