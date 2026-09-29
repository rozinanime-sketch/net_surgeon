package io.github.netsurgeon

/** Функции Rust-ядра из libnet_surgeon_android.so (android/native). */
object NativeBridge {
    init {
        System.loadLibrary("net_surgeon_android")
    }

    /**
     * Поднимает ядро поверх TUN. Владение дескриптором переходит к ядру:
     * закроет его оно само при остановке.
     *
     * @return null, если запустилось, иначе текст ошибки.
     */
    external fun start(tunFd: Int, dataDir: String, lang: String): String?

    external fun stop()

    external fun isRunning(): Boolean

    /** Последние строки лога ядра, по одной на строку. */
    external fun logs(): String

    /**
     * Сеть сменилась — задать её id (для ключей стратегий) и сбросить
     * подобранное под прежнюю сеть состояние (вывод «сеть морозит», TTL
     * приманки). Число хопов до DPI и серверов другое, старые значения ломали
     * бы обход.
     *
     * @param netId стабильный отпечаток сети (интерфейс + DNS), пустая строка —
     *   не определить.
     */
    external fun onNetworkChanged(netId: String)
}
