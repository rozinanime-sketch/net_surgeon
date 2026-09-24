package io.github.netsurgeon

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Проверка новой версии по релизам на GitHub. Раз в сутки, при открытии
 * главного экрана. Само обновление не качает: только показывает ссылку на
 * страницу релиза, APK пользователь скачивает и ставит сам.
 */
object UpdateCheck {
    private const val API =
        "https://api.github.com/repos/rozinanime-sketch/net_surgeon/releases/latest"
    private const val PAGE_PREFIX = "https://github.com/rozinanime-sketch/net_surgeon/"
    private const val DAY_MS = 24 * 60 * 60 * 1000L

    /** Проверяет в фоне, если с прошлой проверки прошли сутки. */
    fun maybeRun(context: Context, done: () -> Unit) {
        val app = context.applicationContext
        if (System.currentTimeMillis() - Prefs.updateCheckedAt(app) < DAY_MS) return
        Thread {
            // Сеть недоступна или GitHub ответил не то — попробуем в другой
            // день; время проверки при ошибке не записываем.
            val release = try {
                fetch()
            } catch (e: Exception) {
                return@Thread
            }
            Prefs.saveUpdateCheck(app, release)
            done()
        }.start()
    }

    /**
     * Версия и страница найденного релиза, если он новее установленной.
     * Иначе null.
     */
    fun available(context: Context): Pair<String, String>? {
        val (version, url) = Prefs.update(context) ?: return null
        return if (newer(version, installed(context))) version to url else null
    }

    private fun fetch(): Pair<String, String> {
        val conn = URL(API).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val version = json.getString("tag_name").removePrefix("v")
            val url = json.getString("html_url")
            // Ссылку откроет браузер: пускаем только на страницы своего
            // репозитория, что бы ни пришло в ответе.
            require(url.startsWith(PAGE_PREFIX)) { "чужая ссылка" }
            return version to url
        } finally {
            conn.disconnect()
        }
    }

    private fun installed(context: Context): String =
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0"

    /** 0.10.0 новее 0.9.1: сравниваем числа, а не строки. */
    internal fun newer(candidate: String, current: String): Boolean {
        val a = candidate.split('.').map { it.toIntOrNull() ?: 0 }
        val b = current.split('.').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }
}
