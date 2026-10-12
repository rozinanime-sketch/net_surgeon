package io.github.netsurgeon

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

/**
 * Настройки ядра (config.toml) полями, а не текстом: переключатели для
 * «да/нет», поля ввода для остального. Список полей и запись — общие с
 * терминальным интерфейсом на компьютере (`src/config/editor.rs`): значение
 * не того типа или конфиг, который потом не прочитается, ядро не сохранит.
 *
 * Для того, чего здесь нет, — кнопка «Как текст» внизу.
 */
class SettingsActivity : Activity() {

    private class Field(val path: String, val initial: String, val input: EditText)

    private val textFields = mutableListOf<Field>()

    override fun onResume() {
        super.onResume()
        // Заново при каждом показе: после правки «как текст» значения другие.
        build()
    }

    private fun build() {
        textFields.clear()
        val pad = dp(16)
        val list = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
        }
        list.addView(TextView(this).apply {
            text = getString(R.string.title_settings)
            textSize = 20f
            setTextColor(Color.rgb(120, 170, 255))
            typeface = Typeface.DEFAULT_BOLD
        })
        list.addView(TextView(this).apply {
            text = getString(R.string.hint_settings)
            setTextColor(Color.GRAY)
            setPadding(0, pad / 2, 0, pad / 2)
        })

        val dir = DataFiles.dir(this).absolutePath
        val lang = NativeBridge.lang(this)
        val rows = NativeBridge.configFields(dir, lang).lines().filter { it.isNotBlank() }
        val broken = rows.firstOrNull()?.takeIf { it.startsWith("!\t") }
        if (broken != null) {
            // Конфиг не читается — полями его не показать, только текстом.
            list.addView(TextView(this).apply {
                text = getString(R.string.error_message, broken.removePrefix("!\t"))
                setTextColor(Color.rgb(255, 120, 120))
            })
        } else {
            var group = ""
            for (row in rows) {
                val parts = row.split('\t')
                if (parts.size < 5) continue
                val (groupTitle, label, path, kind) = parts
                val value = parts[4]
                if (groupTitle != group) {
                    group = groupTitle
                    list.addView(TextView(this).apply {
                        text = groupTitle
                        textSize = 16f
                        setTextColor(Color.rgb(120, 170, 255))
                        setPadding(0, pad, 0, pad / 4)
                    })
                }
                if (kind == "bool") list.addView(switch(dir, lang, label, path, value == "true"))
                else addTextField(list, label, path, value)
            }
            list.addView(Button(this).apply {
                text = getString(R.string.save)
                setOnClickListener { saveText(dir, lang) }
            }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        }

        list.addView(Button(this).apply {
            text = getString(R.string.edit_as_text)
            setOnClickListener {
                startActivity(
                    Intent(this@SettingsActivity, EditorActivity::class.java)
                        .putExtra(EditorActivity.EXTRA_FILE, DataFiles.CONFIG)
                        .putExtra(EditorActivity.EXTRA_TITLE, "config.toml")
                        .putExtra(EditorActivity.EXTRA_HINT, getString(R.string.hint_config_text))
                        .putExtra(EditorActivity.EXTRA_MODE, EditorActivity.MODE_CONFIG)
                )
            }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.rgb(20, 20, 35))
            addView(list)
        }
        scroll.padForSystemBars()
        setContentView(scroll)
    }

    /** Переключатель сохраняется сразу: отдельная кнопка для него лишняя. */
    @Suppress("DEPRECATION")
    private fun switch(dir: String, lang: String, label: String, path: String, on: Boolean) =
        Switch(this).apply {
            text = label
            isChecked = on
            setTextColor(Color.LTGRAY)
            setPadding(0, dp(6), 0, dp(6))
            setOnCheckedChangeListener { view, checked ->
                val error = NativeBridge.setConfigField(dir, lang, path, checked.toString())
                if (error != null) {
                    toast(error)
                    view.isChecked = !checked
                } else {
                    Toast.makeText(this@SettingsActivity, R.string.saved, Toast.LENGTH_SHORT).show()
                }
            }
        }

    private fun addTextField(list: LinearLayout, label: String, path: String, value: String) {
        list.addView(TextView(this).apply {
            text = label
            setTextColor(Color.LTGRAY)
            setPadding(0, dp(6), 0, 0)
        })
        val input = EditText(this).apply {
            setText(value)
            setTextColor(Color.WHITE)
            isSingleLine = true
            // Как адрес: клавиатура не ставит заглавных и пробелов после точек.
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_URI or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        list.addView(input, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        textFields += Field(path, value, input)
    }

    /** Сохраняет изменённые поля по одному; ошибку показывает у поля. */
    private fun saveText(dir: String, lang: String) {
        var failed = false
        var saved = 0
        for (field in textFields) {
            val value = field.input.text.toString().trim()
            if (value == field.initial) continue
            val error = NativeBridge.setConfigField(dir, lang, field.path, value)
            if (error != null) {
                field.input.error = error
                failed = true
            } else {
                saved++
            }
        }
        if (!failed) {
            if (saved > 0) Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show()
            finish()
        } else if (saved > 0) {
            // Остальное уже на диске; экран остаётся, чтобы поправить
            // поля с ошибкой.
            toast(getString(R.string.saved_partly))
        }
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}
