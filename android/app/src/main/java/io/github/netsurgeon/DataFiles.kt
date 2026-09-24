package io.github.netsurgeon

import android.content.Context
import java.io.File

/**
 * Файлы данных ядра — те же, что на компьютере: config.toml и списки
 * доменов. Лежат в личной папке приложения, при первом запуске
 * копируются из assets. Существующие файлы не перезаписываются: в них
 * правки пользователя и накопленные стратегии.
 */
object DataFiles {
    const val BYPASS = "bypass_domains.txt"
    const val BLOCK = "block_domains.txt"
    const val TELEGRAM_RELAY = "telegram_relay.txt"
    private val DEFAULTS = listOf("config.toml", BYPASS, BLOCK)

    /** Есть не в каждой сборке: только если при сборке был свой воркер. */
    private val OPTIONAL = listOf(TELEGRAM_RELAY)

    fun dir(context: Context): File = context.filesDir

    fun ensure(context: Context) {
        for (name in DEFAULTS) {
            val target = File(dir(context), name)
            if (target.exists()) continue
            context.assets.open(name).use { input ->
                target.outputStream().use { input.copyTo(it) }
            }
        }
        for (name in OPTIONAL) {
            val target = File(dir(context), name)
            if (target.exists()) continue
            val input = try {
                context.assets.open(name)
            } catch (e: java.io.FileNotFoundException) {
                continue
            }
            input.use { src -> target.outputStream().use { src.copyTo(it) } }
        }
    }

    fun read(context: Context, name: String): String =
        File(dir(context), name).takeIf { it.exists() }?.readText() ?: ""

    /** Через временный файл, как и в ядре: обрезанный список хуже старого. */
    fun write(context: Context, name: String, text: String) {
        val target = File(dir(context), name)
        val tmp = File(dir(context), ".$name.tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(target)) {
            tmp.delete()
            error("не удалось сохранить $name")
        }
    }
}
