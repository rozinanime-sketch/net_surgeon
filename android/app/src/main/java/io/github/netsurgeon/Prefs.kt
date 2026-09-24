package io.github.netsurgeon

import android.content.Context
import android.content.SharedPreferences

/** Настройки самого приложения. Настройки ядра — в config.toml. */
object Prefs {
    private const val AUTOSTART = "autostart"
    private const val UPDATE_CHECKED_AT = "update_checked_at"
    private const val UPDATE_VERSION = "update_version"
    private const val UPDATE_URL = "update_url"

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences("app", Context.MODE_PRIVATE)

    fun autostart(context: Context): Boolean = prefs(context).getBoolean(AUTOSTART, false)

    fun setAutostart(context: Context, on: Boolean) =
        prefs(context).edit().putBoolean(AUTOSTART, on).apply()

    fun updateCheckedAt(context: Context): Long = prefs(context).getLong(UPDATE_CHECKED_AT, 0)

    /** Последний найденный релиз: версия и страница, или null. */
    fun update(context: Context): Pair<String, String>? {
        val p = prefs(context)
        val version = p.getString(UPDATE_VERSION, null) ?: return null
        val url = p.getString(UPDATE_URL, null) ?: return null
        return version to url
    }

    fun saveUpdateCheck(context: Context, release: Pair<String, String>?) {
        prefs(context).edit().apply {
            putLong(UPDATE_CHECKED_AT, System.currentTimeMillis())
            if (release != null) {
                putString(UPDATE_VERSION, release.first)
                putString(UPDATE_URL, release.second)
            }
        }.apply()
    }
}
