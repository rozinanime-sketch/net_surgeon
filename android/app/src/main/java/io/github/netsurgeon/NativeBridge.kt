package io.github.netsurgeon

import android.content.Context

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
     * @param netId отпечаток сети (интерфейс, шлюз, DNS), пустая строка —
     *   не определить.
     */
    external fun onNetworkChanged(netId: String)

    /**
     * Поля config.toml для экрана настроек: по строке на поле,
     * `группа\tподпись\tпуть\tbool|text\tзначение`; ошибка — `!\tтекст`.
     */
    external fun configFields(dataDir: String, lang: String): String

    /** Записывает одно поле. @return null, если сохранено, иначе текст ошибки. */
    external fun setConfigField(dataDir: String, lang: String, path: String, value: String): String?

    /** Разбирается ли текст как config.toml. @return null или текст ошибки. */
    external fun checkConfig(text: String): String?

    /**
     * Язык для ядра: язык ресурсов, а не Locale.getDefault() — так
     * учитывается и язык, выбранный для одного приложения (Android 13+).
     */
    fun lang(context: Context): String =
        if (context.resources.configuration.locales[0].language == "ru") "ru" else "en"
}
