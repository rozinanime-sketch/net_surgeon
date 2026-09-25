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
 * комментарий) или адреса ретранслятора Telegram. Формат тот же, что на
 * компьютере, поэтому файл можно перенести как есть.
 */
class EditorActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val file = intent.getStringExtra(EXTRA_FILE) ?: return finish()
        val title = intent.getStringExtra(EXTRA_TITLE) ?: file
        val hint = intent.getStringExtra(EXTRA_HINT)
            ?: "Домен на строку, поддомены учитываются. Применится после перезапуска обхода."

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
            text = "Сохранить"
            setOnClickListener {
                try {
                    DataFiles.write(this@EditorActivity, file, normalize(editor.text.toString()))
                    Toast.makeText(this@EditorActivity, "Сохранено", Toast.LENGTH_SHORT).show()
                    finish()
                } catch (e: Exception) {
                    Toast.makeText(this@EditorActivity, "Ошибка: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        setContentView(root)
    }

    /**
     * Домены в нижний регистр и без пробелов вовсе — в имени их не бывает,
     * а клавиатура могла вставить их после точек; комментарии как есть.
     */
    private fun normalize(text: String): String =
        text.lines().joinToString("\n") { line ->
            if (line.trimStart().startsWith("#")) line.trimEnd()
            else line.filterNot { it.isWhitespace() }.lowercase()
        }.trimEnd() + "\n"

    companion object {
        const val EXTRA_FILE = "file"
        const val EXTRA_TITLE = "title"
        const val EXTRA_HINT = "hint"
    }
}
