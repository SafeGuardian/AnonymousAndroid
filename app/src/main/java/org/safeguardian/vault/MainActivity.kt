package org.safeguardian.vault

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
import java.util.UUID
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    private val bg = Color.rgb(13, 19, 29)
    private val panel = Color.rgb(25, 35, 49)
    private val mint = Color.rgb(128, 235, 199)
    private val white = Color.rgb(244, 249, 250)
    private val grey = Color.rgb(145, 165, 181)
    private lateinit var auth: AuthStore
    private var key: ByteArray? = null
    private var store: VaultStore? = null
    private var blobs: EncryptedFileStore? = null
    private lateinit var page: LinearLayout
    private var tab = "home"
    private var foreground = false
    private var bioPending = false
    private var busy = false
    private var pendingInput: Uri? = null
    private var pendingOutput: Pair<String, Uri>? = null
    private var exportId: String? = null

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = bg
        window.navigationBarColor = bg
        auth = AuthStore(this)
        render()
    }
    override fun onResume() { super.onResume(); foreground = true }
    override fun onStop() {
        foreground = false
        if (!bioPending) lock()
        super.onStop()
    }
    override fun onDestroy() { closeVault(); super.onDestroy() }

    private fun closeVault() {
        blobs?.clearSession()
        key?.fill(0)
        key = null
        store = null
        blobs = null
    }
    private fun lock() {
        if (key != null) { closeVault(); tab = "home"; render() }
    }
    private fun db(): VaultStore = store ?: error("Сейф заблокирован")
    private fun fs(): EncryptedFileStore = blobs ?: error("Сейф заблокирован")

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun stack() = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    private fun line() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }
    private fun shape(color: Int = panel, radius: Int = 14) =
        GradientDrawable().apply { setColor(color); cornerRadius = dp(radius).toFloat() }
    private fun text(value: String, size: Float = 14f, color: Int = white, bold: Boolean = false) =
        TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        }
    private fun input(hint: String, value: String = "", secret: Boolean = false, lines: Boolean = false) =
        EditText(this).apply {
            this.hint = hint
            setText(value)
            setTextColor(white)
            setHintTextColor(grey)
            textSize = 14f
            inputType = if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                else if (lines) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
                else InputType.TYPE_CLASS_TEXT
            setSingleLine(!lines)
            backgroundTintList = android.content.res.ColorStateList.valueOf(mint)
        }
    private fun button(title: String, highlight: Boolean = false, callback: () -> Unit) =
        text(title, 13f, if (highlight) bg else white, true).apply {
            gravity = Gravity.CENTER
            setPadding(dp(13), dp(14), dp(13), dp(14))
            background = shape(if (highlight) mint else panel)
            setOnClickListener { if (!busy) callback() }
        }
    private fun add(to: LinearLayout, v: View, bottom: Int = 0) {
        to.addView(v, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(bottom) })
    }
    private fun heading(to: LinearLayout, label: String) {
        add(to, text(label, 15f, white, true).apply { setPadding(0, dp(20), 0, dp(12)) })
    }
    private fun card(to: LinearLayout, tag: String, title: String, description: String) {
        val box = stack().apply {
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR,
                intArrayOf(Color.rgb(27, 69, 61), Color.rgb(25, 37, 57))).apply {
                cornerRadius = dp(20).toFloat()
            }
            setPadding(dp(18), dp(18), dp(18), dp(20))
        }
        add(box, text("◈  " + tag, 11f, mint, true))
        add(box, text(title, 19f, white, true).apply { setPadding(0, dp(13), 0, dp(9)) })
        add(box, text(description, 12f, grey))
        add(to, box, 12)
    }

    private fun render() {
        page = stack().apply { setBackgroundColor(bg) }
        setContentView(page)
        val bar = line().apply { setPadding(dp(19), dp(15), dp(19), dp(15)) }
        bar.addView(text("⬡", 26f, mint, true))
        bar.addView(text("  SafeGuardian", 19f, white, true),
            LinearLayout.LayoutParams(0, -2, 1f))
        if (key != null) bar.addView(text("⌑  LOCK", 12f, mint, true).apply {
            setOnClickListener { lock() }
            setPadding(dp(12), dp(10), 0, dp(10))
        })
        else bar.addView(text("●  PRIVATE", 10f, mint, true))
        page.addView(bar)
        val scroll = ScrollView(this).apply { isFillViewport = true }
        page.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        val body = stack().apply { setPadding(dp(19), dp(6), dp(19), dp(20)) }
        scroll.addView(body)
        if (key == null) {
            if (auth.initialized) login(body) else setup(body)
            return
        }
        body.addView(text("PRIVATE WORKSPACE", 10f, mint, true))
        body.addView(text(when (tab) {
            "home" -> "Моё пространство"; "notes" -> "Notes"
            "files" -> "Vault"; "secrets" -> "Secrets"; else -> "Безопасность"
        }, 27f, white, true).apply { setPadding(0, dp(9), 0, dp(18)) })
        runCatching {
            when (tab) {
                "home" -> home(body)
                "notes" -> records(body, "note")
                "files" -> records(body, "file")
                "secrets" -> records(body, "secret")
                else -> settings(body)
            }
        }.onFailure { add(body, text("Ошибка: " + it.message, 12f, Color.RED)) }
        val nav = line().apply {
            setPadding(dp(3), dp(8), dp(3), dp(8))
            background = shape(Color.rgb(16, 26, 36), 0)
        }
        listOf("home" to "⌂\nГлавная", "notes" to "✎\nNotes",
            "files" to "▣\nVault", "secrets" to "✳\nSecrets", "settings" to "⚙\nЗащита")
            .forEach { (id, name) ->
                nav.addView(text(name, 10f, if (id == tab) mint else grey, id == tab).apply {
                    gravity = Gravity.CENTER
                    setPadding(0, dp(8), 0, dp(8))
                    setOnClickListener { tab = id; render() }
                }, LinearLayout.LayoutParams(0, -2, 1f))
            }
        page.addView(nav)
    }

    private fun setup(body: LinearLayout) {
        heading(body, "Создайте личный сейф")
        card(body, "LOCAL ENCRYPTION", "Ваши данные. Ваши правила.",
            "Установите мастер-пароль. Позже можно подключить вход по отпечатку.")
        val p1 = input("Мастер-пароль от 12 символов", secret = true)
        val p2 = input("Повторите мастер-пароль", secret = true)
        add(body, p1, 8)
        add(body, p2, 14)
        add(body, button("Создать сейф", true) {
            val first = p1.text.toString().toCharArray()
            val second = p2.text.toString().toCharArray()
            try {
                if (first.size < 12 || !first.contentEquals(second)) {
                    first.fill('\u0000'); toast("Пароли не совпадают или слишком короткие")
                } else authWithPassword(first, true)
            } finally { second.fill('\u0000') }
        }, 14)
        add(body, text("Recovery key пока не реализован. Потерянный пароль не восстановить.",
            12f, grey))
    }

    private fun login(body: LinearLayout) {
        heading(body, "Разблокировать SafeGuardian")
        card(body, "LOCKED", "Приватное пространство",
            "Открытие сейфа требует криптографической проверки.")
        val p = input("Мастер-пароль", secret = true)
        add(body, p, 12)
        add(body, button("Войти по паролю", true) {
            val chars = p.text.toString().toCharArray()
            p.setText("")
            authWithPassword(chars, false)
        }, 10)
        if (auth.biometricEnabled) {
            add(body, button("◉  Войти по отпечатку") { biometricUnlock() }, 10)
        }
        add(body, text("После сворачивания приложение автоматически блокируется.", 12f, grey))
    }

    private fun authWithPassword(password: CharArray, isNew: Boolean) {
        if (busy) { password.fill('\u0000'); return }
        busy = true
        Thread {
            try {
                val unlocked = if (isNew) auth.create(password) else auth.unlock(password)
                runOnUiThread {
                    busy = false
                    if (foreground && !isFinishing) enter(unlocked)
                    else unlocked.fill(0)
                }
            } catch (_: Exception) {
                runOnUiThread {
                    busy = false
                    toast(if (isNew) "Ошибка создания" else "Неверный пароль или повреждённый ключ")
                    render()
                }
            } finally { password.fill('\u0000') }
        }.start()
    }

    private fun enter(material: ByteArray) {
        try {
            val opened = VaultStore(this, material)
            opened.migrateLegacy()
            closeVault()
            key = material
            store = opened
            blobs = EncryptedFileStore(this, opened, material)
            tab = "home"
            render()
            finishPending()
        } catch (e: Exception) {
            material.fill(0)
            closeVault()
            render()
            toast("Ошибка сейфа: " + e.message)
        }
    }

    private fun biometricAvailable() = BiometricManager.from(this).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    ) == BiometricManager.BIOMETRIC_SUCCESS

    private fun authenticate(cipher: Cipher, enrollment: Boolean) {
        bioPending = true
        try {
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        bioPending = false
                        try {
                            val checked = result.cryptoObject?.cipher
                                ?: error("Не подтверждён криптографический ключ")
                            if (enrollment) {
                                auth.finishBiometricEnrollment(checked,
                                    key ?: error("Сейф заблокирован"))
                                toast("Отпечаток включён")
                                render()
                            } else enter(auth.finishBiometricUnlock(checked))
                        } catch (_: Exception) { toast("Биометрия недоступна. Используйте пароль.") }
                    }
                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        bioPending = false
                        if (code != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                            code != BiometricPrompt.ERROR_CANCELED &&
                            code != BiometricPrompt.ERROR_USER_CANCELED) {
                            toast(message.toString())
                        }
                    }
                })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(if (enrollment) "Подключить отпечаток" else "Вход в SafeGuardian")
                .setSubtitle("Разблокировка ключа Android Keystore")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Использовать пароль")
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            bioPending = false
            toast("Ошибка биометрии: " + e.message)
        }
    }

    private fun biometricUnlock() {
        if (!biometricAvailable()) { toast("Сильная биометрия не настроена"); return }
        runCatching { authenticate(auth.prepareBiometricUnlock(), false) }
            .onFailure { toast("Ключ отпечатка недоступен. Войдите по паролю.") }
    }
    private fun biometricEnable() {
        if (!biometricAvailable()) { toast("Сначала настройте отпечаток в Android"); return }
        runCatching { authenticate(auth.prepareBiometricEnrollment(), true) }
            .onFailure { toast("Не удалось подключить отпечаток") }
    }

    private fun home(body: LinearLayout) {
        val all = db().list()
        card(body, "VAULT UNLOCKED", "Личный цифровой мир",
            "Зашифрованные заметки, документы, пароли и TOTP.")
        add(body, text("Заметки: " + all.count { it.kind == "note" } +
            "    Файлы: " + all.count { it.kind == "file" } +
            "    Секреты: " + all.count { it.kind == "secret" }, 12f, mint), 10)
        heading(body, "Быстрые действия")
        add(body, button("+  Заметка", true) { editNote(null) }, 7)
        add(body, button("+  Зашифровать файл") { importPicker() }, 7)
        add(body, button("+  Учётная запись") { editSecret(null) }, 7)
        heading(body, "Недавние")
        all.take(5).forEach { itemRow(body, it) }
        if (all.isEmpty()) add(body, text("Добавьте первую запись.", 12f, grey))
        heading(body, "MirageSync")
        add(body, text("Сетевой модуль ещё не подключён к Android. " +
            "Данные пока хранятся на устройстве.", 12f, grey))
    }

    private fun records(body: LinearLayout, kind: String) {
        val description = when (kind) {
            "note" -> "Markdown-заметки и поиск"
            "file" -> "Потоковое шифрование файлов до 1 ГиБ"
            else -> "Пароли, TOTP и генератор паролей"
        }
        card(body, "ENCRYPTED LOCALLY", when (kind) {
            "note" -> "Private Notes"; "file" -> "Private Vault"; else -> "Password Manager"
        }, description)
        add(body, button(when (kind) {
            "note" -> "+  Новая заметка"
            "file" -> "+  Импортировать файл"
            else -> "+  Добавить учётную запись"
        }, true) {
            when (kind) {
                "note" -> editNote(null)
                "file" -> importPicker()
                else -> editSecret(null)
            }
        }, 8)
        if (kind == "secret") add(body, button("⚄  Генератор паролей") { generator() }, 8)
        val search = input("⌕  Поиск по названию")
        add(body, search, 10)
        val result = stack()
        add(body, result)
        fun refresh(query: String) {
            result.removeAllViews()
            val items = db().list().filter {
                it.kind == kind && it.title.contains(query.trim(), true)
            }
            if (items.isEmpty()) add(result, text("Записей пока нет.", 12f, grey))
            items.forEach { itemRow(result, it) }
        }
        refresh("")
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                refresh(s?.toString() ?: "")
            }
            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun itemRow(parent: LinearLayout, item: VaultItem) {
        val box = line().apply {
            background = shape()
            setPadding(dp(13), dp(14), dp(13), dp(14))
        }
        box.addView(text(when (item.kind) {
            "note" -> "✎"; "file" -> "▣"; else -> "✳"
        }, 22f, mint).apply { setPadding(0, 0, dp(12), 0) })
        val labels = stack()
        add(labels, text(item.title, 14f, white, true).apply { maxLines = 1 })
        add(labels, text(when (item.kind) {
            "note" -> item.body.replace("\n", " ").take(55)
            "file" -> item.mime
            else -> "Защищённая учётная запись"
        }, 11f, grey).apply { maxLines = 1 })
        box.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
        box.addView(text(if (item.starred) "★" else "›", 20f, mint))
        box.setOnClickListener { when (item.kind) {
            "note" -> editNote(item)
            "file" -> fileActions(item)
            else -> showSecret(item)
        } }
        add(parent, box, 8)
    }

    private fun editNote(current: VaultItem?) {
        val form = stack().apply { setPadding(dp(16), 0, dp(16), 0) }
        val title = input("Заголовок", current?.title ?: "")
        val content = input("Markdown-текст", current?.body ?: "", lines = true).apply {
            minLines = 6; gravity = Gravity.TOP
        }
        add(form, title)
        add(form, content)
        val dialog = AlertDialog.Builder(this)
            .setTitle(if (current == null) "Новая заметка" else "Редактор")
            .setView(form)
            .setPositiveButton("Сохранить") { _, _ ->
                runCatching {
                    db().note(current?.id, title.text.toString(), content.text.toString(),
                        current?.starred ?: false)
                    render()
                }.onFailure { toast(it.message ?: "Ошибка сохранения") }
            }.setNegativeButton("Отмена", null)
        if (current != null) dialog.setNeutralButton("Действия") { _, _ ->
            AlertDialog.Builder(this).setItems(arrayOf("Избранное", "Удалить")) { _, action ->
                if (action == 0) { db().toggleStar(current); render() }
                else deleteConfirm(current)
            }.show()
        }
        dialog.show()
    }

    private fun editSecret(current: VaultItem?) {
        val existing = current?.let { JSONObject(it.body) } ?: JSONObject()
        val form = stack().apply { setPadding(dp(18), dp(5), dp(18), dp(10)) }
        val name = input("Сервис", current?.title ?: "")
        val website = input("Сайт / домен", existing.optString("site"))
        val app = input("Android package (для Autofill)", existing.optString("package"))
        val login = input("Логин", existing.optString("login"))
        val password = input("Пароль", existing.optString("password"))
        val totp = input("TOTP: Base32 или otpauth://", existing.optString("totp"))
        val note = input("Дополнительная заметка", existing.optString("notes"), lines = true)
        listOf(name, website, app, login, password).forEach { add(form, it) }
        add(form, button("⚄  Сгенерировать пароль") {
            password.setText(PasswordTools.generate())
        })
        add(form, totp)
        add(form, note)
        val scroller = ScrollView(this).apply { addView(form) }
        AlertDialog.Builder(this)
            .setTitle(if (current == null) "Новый секрет" else "Редактировать секрет")
            .setView(scroller)
            .setPositiveButton("Сохранить") { _, _ ->
                runCatching {
                    val otp = totp.text.toString().trim()
                    if (otp.isNotEmpty()) PasswordTools.parseTotp(otp)
                    val payload = JSONObject().apply {
                        put("site", website.text.toString().trim())
                        put("package", app.text.toString().trim())
                        put("login", login.text.toString())
                        put("password", password.text.toString())
                        put("totp", otp)
                        put("notes", note.text.toString())
                    }
                    db().save(VaultItem(
                        current?.id ?: UUID.randomUUID().toString(), "secret",
                        name.text.toString().trim().ifBlank { "Новая запись" }.take(200),
                        payload.toString(), "application/vnd.safeguardian.secret",
                        System.currentTimeMillis(), current?.starred ?: false
                    ))
                    render()
                }.onFailure { toast("Ошибка записи: " + it.message) }
            }.setNegativeButton("Отмена", null).show()
    }

    private fun showSecret(item: VaultItem) {
        val data = JSONObject(item.body)
        val otp = data.optString("totp")
        val details = "Логин: " + data.optString("login") +
            "\nСайт: " + data.optString("site") +
            "\nПароль: ••••••••••••" +
            if (otp.isNotBlank()) runCatching {
                val spec = PasswordTools.parseTotp(otp)
                "\nTOTP: " + PasswordTools.totp(spec) + " (" +
                    PasswordTools.remaining(spec) + " сек.)"
            }.getOrElse { "\nTOTP: ошибка" } else ""
        AlertDialog.Builder(this).setTitle(item.title).setMessage(details)
            .setPositiveButton("Копировать пароль") { _, _ ->
                clipboard(data.optString("password"))
            }.setNeutralButton("Действия") { _, _ ->
                AlertDialog.Builder(this).setItems(arrayOf(
                    "Копировать логин", "Показать пароль", "Копировать TOTP",
                    "Изменить", "Избранное", "Удалить"
                )) { _, selected ->
                    when (selected) {
                        0 -> clipboard(data.optString("login"))
                        1 -> AlertDialog.Builder(this).setTitle("Пароль")
                            .setMessage(data.optString("password"))
                            .setPositiveButton("Копировать") { _, _ ->
                                clipboard(data.optString("password"))
                            }.setNegativeButton("Закрыть", null).show()
                        2 -> runCatching {
                            clipboard(PasswordTools.totp(PasswordTools.parseTotp(otp)))
                        }.onFailure { toast("TOTP не настроен") }
                        3 -> editSecret(item)
                        4 -> { db().toggleStar(item); render() }
                        5 -> deleteConfirm(item)
                    }
                }.show()
            }.setNegativeButton("Закрыть", null).show()
    }

    private fun generator() {
        val form = stack().apply { setPadding(dp(16), 0, dp(16), 0) }
        val length = input("Длина 12–128", "24")
        val output = input("Пароль", PasswordTools.generate())
        add(form, length)
        add(form, output)
        val dialog = AlertDialog.Builder(this).setTitle("Генератор паролей")
            .setView(form).setPositiveButton("Копировать") { _, _ ->
                clipboard(output.text.toString())
            }.setNeutralButton("Ещё", null).setNegativeButton("Закрыть", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                val size = length.text.toString().toIntOrNull()
                if (size == null || size !in 12..128) toast("Длина 12–128")
                else output.setText(PasswordTools.generate(size))
            }
        }
        dialog.show()
    }

    private fun clipboard(secret: String) {
        if (secret.isEmpty()) { toast("Нет значения"); return }
        val manager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("SafeGuardian", secret)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        manager.setPrimaryClip(clip)
        toast("Скопировано. Очистка через 30 секунд.")
        Handler(Looper.getMainLooper()).postDelayed({
            if (manager.primaryClip?.getItemAt(0)?.text?.toString() == secret) {
                if (android.os.Build.VERSION.SDK_INT >= 28) manager.clearPrimaryClip()
                else manager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }, 30_000L)
    }

    private fun importPicker() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }, 1001)
    }

    private fun fileActions(item: VaultItem) {
        AlertDialog.Builder(this).setTitle(item.title).setItems(arrayOf(
            "Экспортировать (без шифрования)", "Избранное", "Удалить"
        )) { _, index ->
            when (index) {
                0 -> {
                    exportId = item.id
                    startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = item.mime.ifBlank { "application/octet-stream" }
                        putExtra(Intent.EXTRA_TITLE, item.title)
                    }, 1002)
                }
                1 -> { db().toggleStar(item); render() }
                2 -> deleteConfirm(item)
            }
        }.show()
    }

    private fun deleteConfirm(item: VaultItem) {
        AlertDialog.Builder(this).setTitle("Удалить без восстановления?")
            .setMessage(item.title)
            .setPositiveButton("Удалить") { _, _ ->
                runCatching {
                    if (item.kind == "file") fs().remove(item) else db().remove(item.id)
                    render()
                }.onFailure { toast("Ошибка: " + it.message) }
            }.setNegativeButton("Отмена", null).show()
    }

    @Deprecated("Storage Access Framework request codes")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = if (resultCode == RESULT_OK) data?.data else null
        if (uri == null) { exportId = null; return }
        when (requestCode) {
            1001 -> pendingInput = uri
            1002 -> pendingOutput = exportId?.let { it to uri }
        }
        exportId = null
        if (key != null) finishPending() else render()
    }

    private fun fileName(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) return it.getString(0) ?: "file"
        }
        return "imported-file"
    }

    private fun finishPending() {
        if (key == null || busy) return
        val pendingIn = pendingInput
        val pendingOut = pendingOutput
        if (pendingIn == null && pendingOut == null) return
        pendingInput = null
        pendingOutput = null
        val fileStore = fs()
        val vaultStore = db()
        busy = true
        Thread {
            try {
                if (pendingIn != null) {
                    contentResolver.openInputStream(pendingIn)!!.use {
                        fileStore.import(fileName(pendingIn),
                            contentResolver.getType(pendingIn) ?: "application/octet-stream", it)
                    }
                } else if (pendingOut != null) {
                    val item = vaultStore.load(pendingOut.first)
                    contentResolver.openOutputStream(pendingOut.second, "w")!!.use {
                        fileStore.export(item, it)
                    }
                }
                runOnUiThread {
                    busy = false
                    if (key != null) {
                        tab = "files"
                        render()
                        toast("Операция выполнена")
                    }
                }
            } catch (e: Exception) {
                runOnUiThread { busy = false; toast("Ошибка файла: " + e.message) }
            }
        }.start()
    }

    private fun settings(body: LinearLayout) {
        card(body, "SECURITY", "Защита SafeGuardian",
            "Пароль, сильная биометрия и автоматическая блокировка.")
        add(body, text("AES-256-GCM · ключ защищён паролем\n" +
            "Автоблокировка при сворачивании · FLAG_SECURE", 12f, grey), 13)
        add(body, button(if (auth.biometricEnabled) "Отключить отпечаток"
            else "◉  Включить вход по отпечатку") {
            if (auth.biometricEnabled) {
                AlertDialog.Builder(this).setTitle("Отключить биометрию?")
                    .setPositiveButton("Отключить") { _, _ ->
                        auth.disableBiometric()
                        render()
                    }.setNegativeButton("Отмена", null).show()
            } else biometricEnable()
        }, 9)
        add(body, button("Изменить мастер-пароль") { changePassword() }, 9)
        add(body, button("Настроить автозаполнение Android") {
            startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE,
                Uri.parse("package:" + packageName)))
        }, 9)
        add(body, button("Заблокировать сейф") { lock() }, 13)
        heading(body, "Ограничения текущей версии")
        add(body, text("Нет recovery key, синхронизации MirageSync и облачных резервных " +
            "копий. Удаление приложения или забытый пароль могут привести к потере данных.",
            12f, grey))
    }

    private fun changePassword() {
        val form = stack().apply { setPadding(dp(16), 0, dp(16), 0) }
        val first = input("Новый пароль", secret = true)
        val repeat = input("Повторите", secret = true)
        add(form, first); add(form, repeat)
        AlertDialog.Builder(this).setTitle("Сменить мастер-пароль").setView(form)
            .setPositiveButton("Изменить") { _, _ ->
                val p = first.text.toString().toCharArray()
                val q = repeat.text.toString().toCharArray()
                try {
                    if (p.size < 12 || !p.contentEquals(q)) {
                        p.fill('\u0000'); toast("Пароли не совпадают или слишком короткие")
                    } else {
                        val material = key ?: return@setPositiveButton
                        busy = true
                        Thread {
                            try {
                                auth.changePassword(material, p)
                                runOnUiThread { busy = false; toast("Пароль обновлён") }
                            } catch (e: Exception) {
                                runOnUiThread { busy = false; toast("Ошибка: " + e.message) }
                            } finally { p.fill('\u0000') }
                        }.start()
                    }
                } finally { q.fill('\u0000') }
            }.setNegativeButton("Отмена", null).show()
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
}
