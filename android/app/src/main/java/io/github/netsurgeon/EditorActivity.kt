package io.github.netsurgeon

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/**
 * Правка файла данных как текста: списка доменов (домен на строку, `#` —
 * комментарий), адреса ретранслятора Telegram или config.toml целиком.
 * Формат тот же, что на компьютере, поэтому файл можно перенести как есть.
 */
class EditorActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val file = intent.getStringExtra(EXTRA_FILE) ?: return finish()
        val title = intent.getStringExtra(EXTRA_TITLE) ?: file
        val hint = intent.getStringExtra(EXTRA_HINT)
            ?: getString(R.string.hint_domains)
        val mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_DOMAINS

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            setBackgroundColor(Color.rgb(20, 20, 35))
        }

        root.addView(TextView(this).apply {
            text = title
            textSize = 20f
            setTextColor(Color.rgb(120, 170, 255))
            typeface = Typeface.DEFAULT_BOLD
        })
        root.addView(TextView(this).apply {
            text = hint
            setTextColor(Color.GRAY)
            setPadding(0, pad / 2, 0, pad / 2)
        })

        val editor = EditText(this).apply {
            setText(DataFiles.read(this@EditorActivity, file))
            typeface = Typeface.MONOSPACE
            textSize = 14f
            setTextColor(Color.WHITE)
            gravity = Gravity.TOP or Gravity.START
            // Как адрес, а не как текст: иначе клавиатура (SwiftKey)
            // ставит пробел и заглавную букву после каждой точки, и
            // «a.workers.dev» превращается в «A. Workers. Dev» даже без
            // подсказок.
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_URI or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setHorizontallyScrolling(false)
        }
        root.addView(editor, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        root.addView(Button(this).apply {
            text = getString(R.string.save)
            setOnClickListener {
                try {
                    val text = normalize(editor.text.toString(), mode)
                    // Конфиг, который не прочитается, не сохраняем: со следующего
                    // запуска обход просто не включился бы.
                    if (mode == MODE_CONFIG) {
                        NativeBridge.checkConfig(text)?.let { error(it) }
                    }
                    DataFiles.write(this@EditorActivity, file, text)
                    Toast.makeText(this@EditorActivity, R.string.saved, Toast.LENGTH_SHORT).show()
                    finish()
                } catch (e: Exception) {
                    Toast.makeText(this@EditorActivity, getString(R.string.error_message, e.message ?: ""), Toast.LENGTH_LONG).show()
                }
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        root.padForSystemBars()
        setContentView(root)
    }

    /**
     * Домены в нижний регистр и без пробелов вовсе — в имени их не бывает,
     * а клавиатура могла вставить их после точек; комментарии как есть.
     * Строка `token: …` в файле Telegram — как есть: секрет воркера
     * сравнивается с учётом регистра, и в нижнем регистре он не подходил.
     * config.toml не трогаем вовсе.
     */
    private fun normalize(text: String, mode: String): String {
        if (mode == MODE_CONFIG) return text.trimEnd() + "\n"
        return text.lines().joinToString("\n") { line ->
            when {
                line.trimStart().startsWith("#") -> line.trimEnd()
                mode == MODE_RELAY && isTokenLine(line) -> line.trim()
                else -> line.filterNot { it.isWhitespace() }.lowercase()
            }
        }.trimEnd() + "\n"
    }

    private fun isTokenLine(line: String): Boolean {
        val rest = line.trimStart().removePrefix("token")
        return rest.length < line.trimStart().length && rest.trimStart().let { it.startsWith(":") || it.startsWith("=") }
    }

    companion object {
        const val EXTRA_FILE = "file"
        const val EXTRA_TITLE = "title"
        const val EXTRA_HINT = "hint"
        const val EXTRA_MODE = "mode"
        const val MODE_DOMAINS = "domains"
        const val MODE_RELAY = "relay"
        const val MODE_CONFIG = "config"
    }
}
