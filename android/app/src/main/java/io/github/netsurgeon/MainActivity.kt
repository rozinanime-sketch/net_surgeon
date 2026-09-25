package io.github.netsurgeon

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Главный экран: кнопка включения и состояние. Лог — отдельным экраном
 * ([LogActivity]): пока всё работает, он не нужен.
 *
 * Разметка собрана в коде, без XML и без AndroidX: экран один и простой,
 * а библиотеки интерфейса удвоили бы размер приложения и время сборки.
 */
class MainActivity : Activity() {

    private lateinit var toggle: Button
    private lateinit var status: TextView
    private lateinit var update: TextView
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
            text = getString(R.string.domains)
            setOnClickListener { openEditor(DataFiles.BYPASS, getString(R.string.title_bypass)) }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = getString(R.string.trackers)
            setOnClickListener { openEditor(DataFiles.BLOCK, getString(R.string.title_block)) }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = getString(R.string.telegram)
            setOnClickListener {
                openEditor(
                    DataFiles.TELEGRAM_RELAY, getString(R.string.title_telegram),
                    getString(R.string.hint_telegram)
                )
            }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        root.addView(row, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.addView(CheckBox(this).apply {
            text = getString(R.string.autostart)
            setTextColor(Color.LTGRAY)
            isChecked = Prefs.autostart(this@MainActivity)
            setOnCheckedChangeListener { _, on -> Prefs.setAutostart(this@MainActivity, on) }
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.always_on_hint)
            textSize = 12f
            setTextColor(Color.GRAY)
            setOnClickListener {
                startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
            }
        })

        update = TextView(this).apply {
            textSize = 15f
            setTextColor(Color.rgb(255, 200, 90))
            setPadding(0, pad / 2, 0, 0)
            visibility = View.GONE
        }
        root.addView(update, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        // Пустое место забирает остаток экрана: кнопка лога — в самом низу.
        root.addView(View(this), LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        root.addView(Button(this).apply {
            text = getString(R.string.log)
            setOnClickListener { startActivity(Intent(this@MainActivity, LogActivity::class.java)) }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.padForSystemBars()
        setContentView(root)
        // После поворота экрана intent тот же: второй раз не включаем.
        if (savedInstanceState == null) startIfAsked(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        startIfAsked(intent)
    }

    /** Экран открыт плиткой, у которой не было разрешения на VPN. */
    private fun startIfAsked(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_START, false) != true) return
        intent.removeExtra(EXTRA_START)
        if (!NativeBridge.isRunning()) onToggle()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
        showUpdate()
        UpdateCheck.maybeRun(this) { runOnUiThread { showUpdate() } }
    }

    private fun showUpdate() {
        val (version, url) = UpdateCheck.available(this) ?: run {
            update.visibility = View.GONE
            return
        }
        update.text = getString(R.string.update_available, version)
        update.setOnClickListener { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
        update.visibility = View.VISIBLE
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun render() {
        val running = NativeBridge.isRunning()
        status.text = getString(if (running) R.string.status_on else R.string.status_off)
        status.setTextColor(if (running) Color.rgb(120, 220, 120) else Color.GRAY)
        toggle.text = getString(if (running) R.string.turn_off else R.string.turn_on)
    }

    private fun onToggle() {
        if (NativeBridge.isRunning()) {
            startService(SurgeonVpnService.stopIntent(this))
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
        // Без разрешения обход тоже работает, только уведомление с кнопкой
        // «Выключить» не видно. Спрашиваем один раз, при первом включении.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
        startForegroundService(SurgeonVpnService.startIntent(this))
    }

    private fun openEditor(file: String, title: String, hint: String? = null) {
        startActivity(
            Intent(this, EditorActivity::class.java)
                .putExtra(EditorActivity.EXTRA_FILE, file)
                .putExtra(EditorActivity.EXTRA_TITLE, title)
                .putExtra(EditorActivity.EXTRA_HINT, hint)
        )
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_START = "start"
        private const val REQUEST_VPN = 1
        private const val REQUEST_NOTIFICATIONS = 2
    }
}
