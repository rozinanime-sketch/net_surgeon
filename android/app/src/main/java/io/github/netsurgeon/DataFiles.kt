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
    private const val CONFIG = "config.toml"
    private val DEFAULTS = listOf(CONFIG, BYPASS, BLOCK, SMART_DNS)

    /**
     * Настройки, появившиеся после первых версий. В уже установленном
     * приложении config.toml старый и не перезаписывается, поэтому без
     * них новая возможность молча не включилась бы. Дописываем из assets
     * только отсутствующие ключи, правки пользователя не трогаем.
     */
    private val ADDED_KEYS = listOf("smart_dns_provider", "smart_dns_bootstrap_ip")

    /**
     * Домены, добавленные в список обхода после первых версий. Как и
     * настройки, в старый bypass_domains.txt сами не попадут. Каждый
     * дописывается один раз: если пользователь его потом удалит, при
     * следующем запуске он не вернётся — предложенные помним в ADDED_MARK.
     */
    private val ADDED_BYPASS = listOf("youtubei.googleapis.com")
    private const val ADDED_MARK = ".added_bypass"

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
        addMissingKeys(context)
        addMissingBypass(context)
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

    private fun addMissingKeys(context: Context) {
        val target = File(dir(context), CONFIG)
        val current = target.readText()
        val present = current.lineSequence().map { it.substringBefore('=').trim() }.toSet()
        val shipped = context.assets.open(CONFIG).bufferedReader().use { it.readText() }
        val missing = shipped.lineSequence()
            .filter { line -> line.substringBefore('=').trim().let { it in ADDED_KEYS && it !in present } }
            .toList()
        if (missing.isEmpty()) return
        // Ключи верхнего уровня: в TOML их нельзя дописать после первой
        // [секции], иначе они попадут в неё. Вставляем перед ней.
        val lines = current.lines().toMutableList()
        val section = lines.indexOfFirst { it.trimStart().startsWith("[") }.takeIf { it >= 0 } ?: lines.size
        lines.addAll(section, missing + "")
        write(context, CONFIG, lines.joinToString("\n"))
    }

    private fun addMissingBypass(context: Context) {
        val mark = File(dir(context), ADDED_MARK)
        val offered = mark.takeIf { it.exists() }?.readLines()?.toSet() ?: emptySet()
        val fresh = ADDED_BYPASS.filter { it !in offered }
        if (fresh.isEmpty()) return
        val current = read(context, BYPASS)
        val present = current.lineSequence().map { it.trim().lowercase() }.toSet()
        val missing = fresh.filter { it !in present }
        if (missing.isNotEmpty()) {
            val sep = if (current.isEmpty() || current.endsWith("\n")) "" else "\n"
            write(context, BYPASS, current + sep + missing.joinToString("\n") + "\n")
        }
        mark.writeText((offered + fresh).joinToString("\n") + "\n")
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
