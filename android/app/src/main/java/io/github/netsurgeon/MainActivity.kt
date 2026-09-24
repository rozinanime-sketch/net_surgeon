package io.github.netsurgeon

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * Главный экран: кнопка включения, состояние и лог ядра.
 *
 * Разметка собрана в коде, без XML и без AndroidX: экран один и простой,
 * а библиотеки интерфейса удвоили бы размер приложения и время сборки.
 */
class MainActivity : Activity() {

    private lateinit var toggle: Button
    private lateinit var status: TextView
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
        DataFiles.ensure(this)

        val pad = dp(16)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            setBackgroundColor(Color.rgb(20, 20, 35))
        }

        root.addView(TextView(this).apply {
            text = "NET SURGEON"
            textSize = 22f
            setTextColor(Color.rgb(120, 170, 255))
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        status = TextView(this).apply {
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(0, pad, 0, pad)
        }
        root.addView(status, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        toggle = Button(this).apply {
            textSize = 18f
            setOnClickListener { onToggle() }
        }
        root.addView(toggle, LinearLayout.LayoutParams(MATCH_PARENT, dp(64)))

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        row.addView(Button(this).apply {
            text = "Домены"
            setOnClickListener { openEditor(DataFiles.BYPASS, "Домены для обхода") }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = "Трекеры"
            setOnClickListener { openEditor(DataFiles.BLOCK, "Блокировка трекеров") }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        root.addView(row, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.addView(TextView(this).apply {
            text = "Лог"
            setTextColor(Color.GRAY)
            setPadding(0, pad, 0, dp(4))
        })

        log = TextView(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.LTGRAY)
            setTextIsSelectable(true)
        }
        logScroll = ScrollView(this).apply { addView(log) }
        root.addView(logScroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

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
        val running = NativeBridge.isRunning()
        status.text = if (running) "Обход включён" else "Выключено"
        status.setTextColor(if (running) Color.rgb(120, 220, 120) else Color.GRAY)
        toggle.text = if (running) "Выключить" else "Включить"

        val text = NativeBridge.logs()
        if (text != log.text.toString()) {
            // Следим за концом лога, только если пользователь и так внизу:
            // иначе нельзя было бы прокрутить вверх и почитать.
            val atBottom = !logScroll.canScrollVertically(1)
            log.text = text
            if (atBottom) logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun onToggle() {
        if (NativeBridge.isRunning()) {
            startService(Intent(this, SurgeonVpnService::class.java).setAction(SurgeonVpnService.ACTION_STOP))
            return
        }
        // Первый раз система спрашивает разрешение на VPN.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            startVpn()
        }
    }

    @Deprecated("Activity без AndroidX: другого способа получить ответ нет")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) startVpn()
    }

    private fun startVpn() {
        startService(Intent(this, SurgeonVpnService::class.java))
    }

    private fun openEditor(file: String, title: String) {
        startActivity(
            Intent(this, EditorActivity::class.java)
                .putExtra(EditorActivity.EXTRA_FILE, file)
                .putExtra(EditorActivity.EXTRA_TITLE, title)
        )
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    companion object {
        private const val REQUEST_VPN = 1
    }
}
