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
    const val SMART_DNS = "smart_dns_domains.txt"
    const val PIN = "pin_strategies.txt"
    const val CONFIG = "config.toml"
    private val DEFAULTS = listOf(CONFIG, BYPASS, BLOCK, SMART_DNS, PIN)

    // Ключи, которых нет в старом config.toml (умный DNS), ядро подставляет
    // само теми же значениями (src/config/mod.rs) — дописывать их сюда не
    // нужно.

    // Новые домены в уже существующие списки дописывает ядро при запуске
    // (src/config/list_updates.rs), с теми же файлами-метками, что были здесь.

    /** Есть не в каждой сборке: только если при сборке был свой воркер. */
    private val OPTIONAL = listOf(TELEGRAM_RELAY)

    fun dir(context: Context): File = context.filesDir

    fun ensure(context: Context) {
        for (name in DEFAULTS + OPTIONAL) {
            if (File(dir(context), name).exists()) continue
            val bytes = try {
                context.assets.open(name).use { it.readBytes() }
            } catch (e: java.io.FileNotFoundException) {
                continue // необязательного файла в этой сборке нет
            }
            // Через временный файл: убитый посреди копирования процесс
            // оставлял обрезанный файл, а существующий больше не копируется.
            write(context, name, bytes)
        }
    }

    fun read(context: Context, name: String): String =
        File(dir(context), name).takeIf { it.exists() }?.readText() ?: ""

    fun write(context: Context, name: String, text: String) = write(context, name, text.toByteArray())

    /**
     * Через временный файл, как и в ядре: обрезанный список хуже старого.
     * Перед переименованием данные сбрасываются на диск — иначе после
     * пропажи питания переименование могло оказаться на диске раньше
     * содержимого, и файл оставался пустым.
     */
    private fun write(context: Context, name: String, bytes: ByteArray) {
        val target = File(dir(context), name)
        val tmp = File(dir(context), ".$name.tmp")
        java.io.FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            error(context.getString(R.string.save_failed, name))
        }
    }
}
