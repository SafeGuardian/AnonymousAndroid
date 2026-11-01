package org.safeguardian.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Two distinct ways of *cryptographically unwrapping* one random 256-bit vault
 * data-encryption key:
 *
 * 1. A high-entropy master password, PBKDF2-HMAC-SHA256, AES-256-GCM.
 * 2. An optional Android Keystore auth-per-use key bound to a strong biometric
 *    prompt's CryptoObject.
 *
 * Neither plaintext key nor password is written to disk. The master password
 * is the sole recovery option in v0.2; losing it loses the vault. This is a
 * local vault and is NOT yet multi-device E2EE.
 */
class AuthStore(private val context: Context) {
    private val config = File(context.filesDir, "vault-auth.json")
    private val biometric = File(context.filesDir, "vault-bio.json")
    private val random = SecureRandom()
    private val alias = "SafeGuardian.BiometricWrap.v2"

    val initialized: Boolean get() = config.exists()
    val biometricEnabled: Boolean get() = biometric.exists()

    fun create(password: CharArray): ByteArray {
        require(!initialized) { "Сейф уже настроен" }
        validatePassword(password)
        val key = ByteArray(32).also(random::nextBytes)
        try {
            writePasswordEnvelope(key, password)
        } catch (error: Exception) {
            key.fill(0)
            throw error
        }
        return key
    }

    fun unlock(password: CharArray): ByteArray {
        val json = JSONObject(config.readText())
        require(json.getInt("version") == 2) { "Неизвестная версия хранилища" }
        val salt = decode(json.getString("salt"))
        val iv = decode(json.getString("iv"))
        val wrapped = decode(json.getString("wrapped"))
        require(salt.size == 16 && iv.size == 12 && wrapped.size == 48)
        val rounds = json.getInt("iterations")
        require(rounds in 300_000..2_000_000)
        val passwordKey = derive(password, salt, rounds)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(passwordKey, "AES"), GCMParameterSpec(128, iv))
            cipher.updateAAD(PASSWORD_AAD)
            val result = cipher.doFinal(wrapped)
            require(result.size == 32)
            return result
        } finally {
            passwordKey.fill(0)
            salt.fill(0)
        }
    }

    fun changePassword(masterKey: ByteArray, newPassword: CharArray) {
        require(initialized && masterKey.size == 32)
        validatePassword(newPassword)
        writePasswordEnvelope(masterKey, newPassword)
    }

    private fun writePasswordEnvelope(key: ByteArray, password: CharArray) {
        val salt = ByteArray(16).also(random::nextBytes)
        val wrapKey = derive(password, salt, PBKDF2_ROUNDS)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKey, "AES"))
            cipher.updateAAD(PASSWORD_AAD)
            val json = JSONObject().apply {
                put("version", 2)
                put("kdf", "PBKDF2-HMAC-SHA256")
                put("iterations", PBKDF2_ROUNDS)
                put("salt", encode(salt))
                put("iv", encode(cipher.iv))
                put("wrapped", encode(cipher.doFinal(key)))
            }
            atomicWrite(config, json.toString())
        } finally {
            salt.fill(0)
            wrapKey.fill(0)
        }
    }

    private fun validatePassword(password: CharArray) {
        require(password.size in 12..256) { "Пароль должен содержать от 12 до 256 символов" }
    }

    private fun derive(password: CharArray, salt: ByteArray, rounds: Int): ByteArray {
        val spec = PBEKeySpec(password, salt, rounds, 256)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

    private fun biometricKey(createIfMissing: Boolean): SecretKey {
        val ks = keystore()
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        require(createIfMissing) { "Биометрический ключ недоступен" }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    fun prepareBiometricEnrollment(): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, biometricKey(true))
            updateAAD(BIOMETRIC_AAD)
        }

    fun finishBiometricEnrollment(cipher: Cipher, masterKey: ByteArray) {
        require(masterKey.size == 32 && initialized)
        val iv = cipher.iv
        val sealed = cipher.doFinal(masterKey)
        atomicWrite(biometric, JSONObject().apply {
            put("version", 2)
            put("iv", encode(iv))
            put("wrapped", encode(sealed))
        }.toString())
    }

    fun prepareBiometricUnlock(): Cipher {
        val data = JSONObject(biometric.readText())
        require(data.getInt("version") == 2)
        val iv = decode(data.getString("iv"))
        require(iv.size == 12)
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, biometricKey(false), GCMParameterSpec(128, iv))
            updateAAD(BIOMETRIC_AAD)
        }
    }

    fun finishBiometricUnlock(cipher: Cipher): ByteArray {
        val data = JSONObject(biometric.readText())
        val wrapped = decode(data.getString("wrapped"))
        require(wrapped.size == 48)
        val result = cipher.doFinal(wrapped)
        require(result.size == 32)
        return result
    }

    fun disableBiometric() {
        if (biometric.exists() && !biometric.delete()) error("Не удалось удалить биометрическую обёртку")
        val ks = keystore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun atomicWrite(file: File, data: String) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        try {
            tmp.outputStream().use { output ->
                output.write(data.toByteArray(Charsets.UTF_8))
                if (output is java.io.FileOutputStream) output.fd.sync()
            }
            java.nio.file.Files.move(
                tmp.toPath(), file.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE
            )
        } finally {
            tmp.delete()
        }
    }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun decode(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)

    companion object {
        const val PBKDF2_ROUNDS = 600_000
        private val PASSWORD_AAD = "SafeGuardian/v2/password-wrap".toByteArray()
        private val BIOMETRIC_AAD = "SafeGuardian/v2/biometric-wrap".toByteArray()
    }
}
