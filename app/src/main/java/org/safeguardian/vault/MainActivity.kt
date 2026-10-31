package org.safeguardian.vault

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.database.Cursor
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import kotlin.math.roundToInt

class MainActivity : Activity() {
    private val background = Color.rgb(13, 19, 29)
    private val surface = Color.rgb(25, 35, 49)
    private val mint = Color.rgb(130, 239, 204)
    private val primary = Color.rgb(241, 247, 249)
    private val secondary = Color.rgb(150, 168, 182)
    private lateinit var store: VaultStore
    private lateinit var root: LinearLayout
    private var tab = "notes"
    private var pendingExport: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = background
        window.navigationBarColor = background
        store = VaultStore(this)
        render()
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).roundToInt()
    private fun column() = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    private fun row() = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }

    private fun surfaceShape(color: Int = surface, radius: Int = 17, stroke: Boolean = false) =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = dp(radius).toFloat()
            if (stroke) setStroke(dp(1), Color.rgb(52, 72, 85))
        }

    private fun txt(value: String, size: Float = 14f, color: Int = primary, bold: Boolean = false): TextView =
        TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        }

    private fun pad(view: View, all: Int): View {
        view.setPadding(dp(all), dp(all), dp(all), dp(all))
        return view
    }

    private fun addSection(parent: LinearLayout, title: String) {
        parent.addView(txt(title, 15f, primary, true).apply {
            setPadding(0, dp(22), 0, dp(12))
        })
    }

    private fun action(label: String, filled: Boolean = false, click: () -> Unit): TextView =
        txt(label, 13f, if (filled) background else primary, true).apply {
            gravity = Gravity.CENTER
            background = surfaceShape(if (filled) mint else surface, 13, !filled)
            setPadding(dp(14), dp(14), dp(14), dp(14))
            setOnClickListener { click() }
        }

    private fun render() {
        root = column().apply { setBackgroundColor(this@MainActivity.background) }
        setContentView(root)

        val top = row().apply { setPadding(dp(20), dp(20), dp(20), dp(16)) }
        top.addView(txt("⬡", 28f, mint, true))
        top.addView(txt("  SafeGuardian", 19f, primary, true),
            LinearLayout.LayoutParams(0, -2, 1f))
        top.addView(txt("●  LOCAL", 10f, mint, true))
        root.addView(top)

        val scroller = ScrollView(this).apply { isFillViewport = true }
        root.addView(scroller, LinearLayout.LayoutParams(-1, 0, 1f))
        val body = column().apply { setPadding(dp(20), dp(7), dp(20), dp(22)) }
        scroller.addView(body)
        body.addView(txt("PRIVATE WORKSPACE", 10f, mint, true))
        body.addView(txt(when (tab) {
            "notes" -> "Ваши заметки"
            "files" -> "Ваш сейф"
            else -> "Безопасность"
        }, 28f, primary, true).apply { setPadding(0, dp(9), 0, dp(17)) })

        val hero = column().apply {
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR,
                intArrayOf(Color.rgb(30, 67, 67), Color.rgb(26, 39, 60))).apply {
                cornerRadius = dp(20).toFloat()
            }
            setPadding(dp(18), dp(18), dp(18), dp(18))
        }
        hero.addView(txt("◈  ЗАШИФРОВАНО НА УСТРОЙСТВЕ", 11f, mint, true))
        hero.addView(txt("Ваши данные. Ваши правила.", 17f, primary, true).apply {
            setPadding(0, dp(14), 0, dp(8))
        })
        hero.addView(txt("AES-256-GCM · Android Keystore", 11f, secondary))
        body.addView(hero)

        try {
            when (tab) {
                "notes" -> renderNotes(body)
                "files" -> renderFiles(body)
                else -> renderSettings(body)
            }
        } catch (err: Exception) {
            body.addView(txt("Ошибка чтения сейфа: " + (err.message ?: "unknown"),
                12f, Color.rgb(250, 151, 151)))
        }

        val nav = row().apply {
            setPadding(dp(10), dp(8), dp(10), dp(13))
            background = surfaceShape(Color.rgb(17, 26, 38), 0)
        }
        listOf("notes" to "✎  Заметки", "files" to "▣  Файлы", "settings" to "⚙  Защита")
            .forEach { (id, name) ->
                val b = txt(name, 12f, if (tab == id) mint else secondary, tab == id).apply {
                    gravity = Gravity.CENTER
                    setPadding(dp(4), dp(12), dp(4), dp(12))
                    setOnClickListener { tab = id; render() }
                }
                nav.addView(b, LinearLayout.LayoutParams(0, -2, 1f))
            }
        root.addView(nav)
    }

    private fun renderNotes(body: LinearLayout) {
        addSection(body, "Быстрые действия")
        body.addView(action("+  Создать заметку", filled = true) { editNote(null) })
        val items = store.list().filter { it.kind == "note" }
        addSection(body, "Заметки · " + items.size)
        if (items.isEmpty()) {
            body.addView(txt("Здесь появятся ваши зашифрованные заметки.", 13f, secondary).apply {
                setPadding(dp(4), dp(12), 0, dp(12))
            })
        }
        items.forEach { item ->
            val card = column().apply {
                background = surfaceShape()
                setPadding(dp(16), dp(14), dp(16), dp(14))
            }
            card.addView(txt(item.title, 15f, primary, true))
            card.addView(txt(item.body.replace("\n", " ").take(105), 12f, secondary).apply {
                setPadding(0, dp(8), 0, 0)
            })
            card.setOnClickListener { editNote(item) }
            body.addView(card, LinearLayout.LayoutParams(-1, -2).apply {
                bottomMargin = dp(9)
            })
        }
    }

    private fun renderFiles(body: LinearLayout) {
        addSection(body, "Зашифрованные файлы")
        body.addView(action("+  Импортировать файл", filled = true) { openPicker() })
        body.addView(txt("До 8 МиБ на файл в MVP. Содержимое и имя шифруются вместе.",
            11f, secondary).apply { setPadding(dp(2), dp(12), dp(2), 0) })
        val items = store.list().filter { it.kind == "file" }
        addSection(body, "Файлы · " + items.size)
        if (items.isEmpty()) body.addView(txt("В сейфе пока нет файлов.", 13f, secondary))
        items.forEach { item ->
            val card = row().apply {
                background = surfaceShape()
                setPadding(dp(14), dp(15), dp(14), dp(15))
            }
            card.addView(txt("▣", 24f, mint))
            val labels = column().apply { setPadding(dp(14), 0, 0, 0) }
            labels.addView(txt(item.title, 13f, primary, true).apply { maxLines = 1 })
            labels.addView(txt(item.mime, 10f, secondary))
            card.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
            card.addView(txt("›", 24f, secondary))
            card.setOnClickListener { fileOptions(item) }
            body.addView(card, LinearLayout.LayoutParams(-1, -2).apply {
                bottomMargin = dp(9)
            })
        }
    }

    private fun renderSettings(body: LinearLayout) {
        addSection(body, "Локальная защита")
        val card = column().apply {
            background = surfaceShape()
            setPadding(dp(16), dp(15), dp(16), dp(15))
        }
        card.addView(txt("●  Шифрование включено", 14f, mint, true))
        card.addView(txt(
            "Каждая заметка и каждый файл шифруются AES-256-GCM. " +
            "Ключ хранится в Android Keystore. Имена файлов не сохраняются открытым текстом.",
            12f, secondary
        ).apply { setPadding(0, dp(11), 0, 0) })
        card.addView(txt(
            "Демо не включает мастер-пароль, восстановление после потери телефона, " +
            "сетевую синхронизацию, биометрическую аутентификацию и аудит.",
            12f, secondary
        ).apply { setPadding(0, dp(11), 0, 0) })
        body.addView(card)
        addSection(body, "Данные")
        body.addView(txt(
            "Хранилище доступно только этому приложению. Резервное копирование Android отключено, " +
            "поэтому удаление приложения удалит данные без возможности восстановления.",
            12f, secondary
        ))
    }

    private fun editNote(existing: VaultItem?) {
        val form = column().apply { setPadding(dp(18), dp(8), dp(18), 0) }
        val title = EditText(this).apply {
            hint = "Заголовок"
            setText(existing?.title ?: "")
            setSingleLine(true)
        }
        val body = EditText(this).apply {
            hint = "Текст заметки"
            setText(existing?.body ?: "")
            minLines = 6
            gravity = Gravity.TOP
        }
        form.addView(title)
        form.addView(body)
        val builder = AlertDialog.Builder(this)
            .setTitle(if (existing == null) "Новая заметка" else "Изменить заметку")
            .setView(form)
            .setPositiveButton("Сохранить") { _, _ ->
                runCatching {
                    store.note(existing?.id, title.text.toString(), body.text.toString())
                    render()
                }.onFailure { fail(it) }
            }
            .setNegativeButton("Отмена", null)
        if (existing != null) builder.setNeutralButton("Удалить") { _, _ ->
            AlertDialog.Builder(this).setMessage("Удалить заметку без возможности восстановления?")
                .setPositiveButton("Удалить") { _, _ ->
                    runCatching { store.remove(existing.id); render() }.onFailure { fail(it) }
                }.setNegativeButton("Отмена", null).show()
        }
        builder.show()
    }

    private fun fileOptions(item: VaultItem) {
        AlertDialog.Builder(this).setTitle(item.title)
            .setItems(arrayOf("Экспортировать расшифрованную копию", "Удалить")) { _, which ->
                if (which == 0) {
                    pendingExport = item.id
                    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = item.mime.ifBlank { "application/octet-stream" }
                        putExtra(Intent.EXTRA_TITLE, item.title)
                    }
                    startActivityForResult(intent, 1002)
                } else {
                    AlertDialog.Builder(this).setMessage("Удалить файл без восстановления?")
                        .setPositiveButton("Удалить") { _, _ ->
                            runCatching { store.remove(item.id); render() }.onFailure { fail(it) }
                        }.setNegativeButton("Отмена", null).show()
                }
            }.show()
    }

    private fun openPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(intent, 1001)
    }

    private fun displayName(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) return cursor.getString(0) ?: "file"
        }
        return "imported-file"
    }

    @Deprecated("MVP uses platform SAF request codes")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        val uri = data.data!!
        runCatching {
            when (requestCode) {
                1001 -> {
                    val bytes = ByteArrayOutputStream()
                    contentResolver.openInputStream(uri)!!.use { input ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (bytes.size() + count > VaultStore.MAX_IMPORT_BYTES)
                                error("Файл превышает ограничение 8 МиБ")
                            bytes.write(buffer, 0, count)
                        }
                    }
                    store.addFile(displayName(uri), contentResolver.getType(uri) ?: "application/octet-stream", bytes.toByteArray())
                    tab = "files"
                    render()
                    Toast.makeText(this, "Файл зашифрован и сохранён", Toast.LENGTH_SHORT).show()
                }
                1002 -> {
                    val id = pendingExport ?: error("No pending file")
                    pendingExport = null
                    val file = store.load(id)
                    contentResolver.openOutputStream(uri, "w")!!.use { it.write(store.fileBytes(file)) }
                    Toast.makeText(this, "Экспорт завершён", Toast.LENGTH_SHORT).show()
                }
            }
        }.onFailure { fail(it) }
    }

    private fun fail(error: Throwable) {
        Toast.makeText(this, error.message ?: "Ошибка", Toast.LENGTH_LONG).show()
    }
}
