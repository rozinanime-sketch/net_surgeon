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
}
