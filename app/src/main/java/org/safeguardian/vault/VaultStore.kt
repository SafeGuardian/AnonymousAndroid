package org.safeguardian.vault

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Local-only encrypted storage.
 * Keystore AES-256-GCM protects each JSON record including its title and MIME.
 * Device-bound: a future cross-device protocol will require a separate key.
 */
data class VaultItem(
    val id: String,
    val kind: String,
    val title: String,
    val body: String,
    val mime: String,
    val modified: Long
)

class VaultStore(context: Context) {
    private val dir = File(context.filesDir, "vault").apply { mkdirs() }
    private val alias = "SafeGuardian.LocalVault.v1"
    private val random = SecureRandom()

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        (store.getKey(alias, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun path(id: String): File {
        require(Regex("[a-f0-9-]{36}").matches(id)) { "Invalid record ID" }
        return File(dir, "$id.sg")
    }

    fun save(item: VaultItem) {
        val data = JSONObject().apply {
            put("version", 1)
            put("id", item.id)
            put("kind", item.kind)
            put("title", item.title)
            put("body", item.body)
            put("mime", item.mime)
            put("modified", item.modified)
        }.toString().toByteArray(Charsets.UTF_8)

        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(), GCMParameterSpec(128, nonce))
        val encrypted = cipher.doFinal(data)
        val target = path(item.id)
        val temporary = File(dir, item.id + ".tmp")
        try {
            temporary.outputStream().use {
                it.write(byteArrayOf(1))
                it.write(nonce)
                it.write(encrypted)
                if (it is java.io.FileOutputStream) it.fd.sync()
            }
            try {
                Files.move(temporary.toPath(), target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temporary.delete()
        }
    }

    fun load(id: String): VaultItem {
        val raw = path(id).readBytes()
        require(raw.size >= 29 && raw[0] == 1.toByte()) { "Invalid encrypted record" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(1, 13)))
        val payload = cipher.doFinal(raw.copyOfRange(13, raw.size))
        val json = JSONObject(String(payload, Charsets.UTF_8))
        require(json.getInt("version") == 1 && json.getString("id") == id)
        return VaultItem(
            id = id,
            kind = json.getString("kind"),
            title = json.getString("title"),
            body = json.getString("body"),
            mime = json.optString("mime", "application/octet-stream"),
            modified = json.getLong("modified")
        )
    }

    fun list(): List<VaultItem> =
        dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(".sg") }
            ?.map { load(it.name.removeSuffix(".sg")) }
            ?.sortedByDescending { it.modified }
            ?: emptyList()

    fun remove(id: String) {
        if (path(id).exists() && !path(id).delete()) error("Cannot delete record")
    }

    fun note(id: String? = null, title: String, text: String) {
        val safeTitle = title.trim().ifBlank { "Без названия" }.take(200)
        require(text.length <= 1_000_000) { "Note is too large" }
        save(VaultItem(id ?: UUID.randomUUID().toString(), "note", safeTitle, text,
            "text/plain", System.currentTimeMillis()))
    }

    fun addFile(filename: String, mime: String, bytes: ByteArray) {
        require(bytes.size <= MAX_IMPORT_BYTES) { "Maximum import size is 8 MiB" }
        save(VaultItem(
            UUID.randomUUID().toString(), "file", filename.take(200),
            Base64.encodeToString(bytes, Base64.NO_WRAP),
            mime, System.currentTimeMillis()
        ))
    }

    fun fileBytes(item: VaultItem): ByteArray {
        require(item.kind == "file")
        return Base64.decode(item.body, Base64.DEFAULT)
    }

    companion object { const val MAX_IMPORT_BYTES = 8 * 1024 * 1024 }
}
