package io.github.netsurgeon

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Лог ядра — отдельным экраном, а не на главном.
 *
 * Пользователю он не нужен, пока всё работает, а строки вроде
 * «✗ SOCKS5 CONNECT ошибка» на главном экране выглядели как поломка.
 * Нужен он, когда что-то не открывается: разобраться самому или
 * отправить автору — поэтому здесь «Копировать» и «Поделиться».
 */
class LogActivity : Activity() {

    private lateinit var log: TextView
    private lateinit var logScroll: ScrollView
    private val handler = Handler(Looper.getMainLooper())

    private val refresh = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            setBackgroundColor(Color.rgb(20, 20, 35))
        }

        root.addView(TextView(this).apply {
            text = "Лог"
            textSize = 20f
            setTextColor(Color.rgb(120, 170, 255))
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, pad / 2)
        })

        log = TextView(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.LTGRAY)
            setTextIsSelectable(true)
        }
        logScroll = ScrollView(this).apply { addView(log) }
        root.addView(logScroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        row.addView(Button(this).apply {
            text = "Копировать"
            setOnClickListener { copy() }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = "Поделиться"
            setOnClickListener { share() }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        root.addView(row, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.padForSystemBars()
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun render() {
        val text = NativeBridge.logs()
        if (text != log.text.toString()) {
            // Следим за концом лога, только если пользователь и так внизу:
            // иначе нельзя было бы прокрутить вверх и почитать.
            val atBottom = !logScroll.canScrollVertically(1)
            log.text = text.ifEmpty { "Пусто: обход ещё не включали." }
            if (atBottom) logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun copy() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("net_surgeon log", NativeBridge.logs()))
        Toast.makeText(this, "Скопировано", Toast.LENGTH_SHORT).show()
    }

    private fun share() {
        val send = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, "Лог net_surgeon")
            .putExtra(Intent.EXTRA_TEXT, NativeBridge.logs())
        startActivity(Intent.createChooser(send, "Отправить лог"))
    }
}
