package org.safeguardian.vault

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import android.widget.RemoteViews
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
import javax.crypto.Cipher

/** Authentication activity invoked only through an Android-system Autofill
 *  challenge. No credential is returned until authenticated, scoped by exact
 *  Android package and explicitly selected by the user. */
class AutofillUnlockActivity : FragmentActivity() {
    private lateinit var auth: AuthStore
    private var packageId = ""
    private var loginId: AutofillId? = null
    private var passwordId: AutofillId? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = Color.rgb(13, 19, 29)
        window.navigationBarColor = Color.rgb(13, 19, 29)
        auth = AuthStore(this)
        packageId = intent.getStringExtra(EXTRA_CALLER) ?: ""
        @Suppress("DEPRECATION")
        loginId = intent.getParcelableExtra(EXTRA_LOGIN_ID)
        @Suppress("DEPRECATION")
        passwordId = intent.getParcelableExtra(EXTRA_PASSWORD_ID)
        if (!auth.initialized || packageId.isEmpty() || passwordId == null ||
            GuardianAutofillService.isBrowser(packageId)) {
            cancel()
            return
        }
        showPassword()
    }

    private fun showPassword() {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(13, 19, 29))
            setPadding(44, 90, 44, 35)
        }
        val title = TextView(this).apply {
            text = "SafeGuardian Autofill"
            textSize = 22f
            setTextColor(Color.rgb(128, 235, 199))
        }
        wrapper.addView(title)
        val message = TextView(this).apply {
            text = "Запрос приложения: " + packageId +
                "\nДля передачи учётной записи разблокируйте сейф."
            textSize = 13f
            setTextColor(Color.WHITE)
            setPadding(0, 30, 0, 25)
        }
        wrapper.addView(message)
        val password = EditText(this).apply {
            hint = "Мастер-пароль"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setTextColor(Color.WHITE)
            setHintTextColor(Color.LTGRAY)
        }
        wrapper.addView(password)
        val submit = TextView(this).apply {
            text = "Разблокировать"
            textSize = 16f
            setTextColor(Color.rgb(128, 235, 199))
            gravity = Gravity.CENTER
            setPadding(25, 36, 25, 36)
            setOnClickListener {
                val chars = password.text.toString().toCharArray()
                password.setText("")
                Thread {
                    try {
                        val key = auth.unlock(chars)
                        runOnUiThread { unlocked(key) }
                    } catch (_: Exception) {
                        runOnUiThread {
                            Toast.makeText(this@AutofillUnlockActivity,
                                "Неверный пароль", Toast.LENGTH_SHORT).show()
                        }
                    } finally { chars.fill('\u0000') }
                }.start()
            }
        }
        wrapper.addView(submit)
        if (auth.biometricEnabled) {
            val bio = TextView(this).apply {
                text = "◉  Войти по отпечатку"
                textSize = 15f
                setTextColor(Color.WHITE)
                gravity = Gravity.CENTER
                setPadding(20, 30, 20, 30)
                setOnClickListener { promptBiometric() }
            }
            wrapper.addView(bio)
        }
        setContentView(wrapper)
    }

    private fun promptBiometric() {
        if (BiometricManager.from(this).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ) != BiometricManager.BIOMETRIC_SUCCESS) return
        try {
            val cipher = auth.prepareBiometricUnlock()
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        runCatching {
                            val verified = result.cryptoObject?.cipher
                                ?: error("No authorized cipher")
                            unlocked(auth.finishBiometricUnlock(verified))
                        }.onFailure {
                            Toast.makeText(this@AutofillUnlockActivity,
                                "Используйте мастер-пароль", Toast.LENGTH_LONG).show()
                        }
                    }
                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (code != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                            Toast.makeText(this@AutofillUnlockActivity,
                                message, Toast.LENGTH_SHORT).show()
                        }
                    }
                })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("SafeGuardian Autofill")
                .setSubtitle("Открыть сохранённые учётные записи")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("По паролю")
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) {
            Toast.makeText(this, "Биометрия не настроена", Toast.LENGTH_LONG).show()
        }
    }

    private fun unlocked(key: ByteArray) {
        try {
            val vault = VaultStore(this, key)
            val options = vault.list().filter { item ->
                item.kind == "secret" &&
                    JSONObject(item.body).optString("package") == packageId
            }
            if (options.isEmpty()) {
                Toast.makeText(this, "Нет записей для " + packageId,
                    Toast.LENGTH_LONG).show()
                cancel()
                return
            }
            AlertDialog.Builder(this)
                .setTitle("Выберите учётную запись")
                .setItems(options.map { it.title + " • " +
                    JSONObject(it.body).optString("login") }.toTypedArray()) { _, index ->
                    returnCredential(options[index])
                }.setNegativeButton("Отмена") { _, _ -> cancel() }
                .setOnCancelListener { cancel() }
                .show()
        } catch (_: Exception) {
            cancel()
        } finally { key.fill(0) }
    }

    private fun returnCredential(record: VaultItem) {
        try {
            val json = JSONObject(record.body)
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, "SafeGuardian — " + record.title)
            }
            val builder = Dataset.Builder()
            loginId?.let {
                builder.setValue(it, AutofillValue.forText(json.optString("login")), presentation)
            }
            builder.setValue(passwordId ?: error("Password field missing"),
                AutofillValue.forText(json.optString("password")), presentation)
            val response = FillResponse.Builder().addDataset(builder.build()).build()
            setResult(Activity.RESULT_OK, Intent().apply {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            })
            finish()
        } catch (_: Exception) { cancel() }
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    companion object {
        const val EXTRA_CALLER = "org.safeguardian.vault.CALLER"
        const val EXTRA_LOGIN_ID = "org.safeguardian.vault.USERNAME_FIELD"
        const val EXTRA_PASSWORD_ID = "org.safeguardian.vault.PASSWORD_FIELD"
    }
}
