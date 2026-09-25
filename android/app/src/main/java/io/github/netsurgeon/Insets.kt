package io.github.netsurgeon

import android.os.Build
import android.view.View
import android.view.WindowInsets

/**
 * Отступы под строку состояния и панель навигации поверх собственных.
 *
 * С Android 15 окно приложения всегда во весь экран, и системные панели
 * лежат поверх него: нижняя кнопка («Лог», «Сохранить») уходила под
 * панель навигации и почти не нажималась.
 */
fun View.padForSystemBars() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
    val left = paddingLeft
    val top = paddingTop
    val right = paddingRight
    val bottom = paddingBottom
    setOnApplyWindowInsetsListener { view, insets ->
        val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
        view.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + bars.bottom)
        insets
    }
}
