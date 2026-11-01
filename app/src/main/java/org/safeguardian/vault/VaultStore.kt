package org.safeguardian.vault

import android.content.Context
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
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Local vault records: v2 AES-256-GCM, random 12-byte nonce per record and
 * authenticated random record ID. Filenames, note bodies, MIME and favourites
 * are encrypted. Key is provided ONLY after a successful password/biometric
 * unwrap by AuthStore. Never write the plaintext key to files or preferences.
 */
data class VaultItem(
    val id: String,
    val kind: String,
    val title: String,
    val body: String,
    val mime: String,
    val modified: Long,
    val starred: Boolean = false
)

class VaultStore(context: Context, key: ByteArray) {
    private val dir = File(context.filesDir, "vault").apply { mkdirs() }
    private val master = SecretKeySpec(key, "AES")
    private val random = SecureRandom()
    private val legacyAlias = "SafeGuardian.LocalVault.v1"

    init { require(key.size == 32) }

    private fun path(id: String): File {
        require(Regex("[a-f0-9-]{36}").matches(id)) { "Invalid record ID" }
        return File(dir, "$id.sg")
    }

    private fun aad(id: String) =
        ("SafeGuardian/v2/record/" + id).toByteArray(Charsets.UTF_8)

    fun save(item: VaultItem) {
        val bytes = JSONObject().apply {
            put("version", 2)
            put("id", item.id)
            put("kind", item.kind)
            put("title", item.title)
            put("body", item.body)
            put("mime", item.mime)
            put("modified", item.modified)
            put("starred", item.starred)
        }.toString().toByteArray(Charsets.UTF_8)

        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, master, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(item.id))
        val ciphertext = cipher.doFinal(bytes)
        val target = path(item.id)
        val temporary = File(dir, item.id + ".tmp")
        try {
            temporary.outputStream().use {
                it.write(byteArrayOf(2))
                it.write(nonce)
                it.write(ciphertext)
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

    private fun legacyKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        return ks.getKey(legacyAlias, null) as? SecretKey
            ?: error("Старый ключ сейфа недоступен. Миграция невозможна.")
    }

    private fun decrypt(id: String): JSONObject {
        val raw = path(id).readBytes()
        require(raw.size >= 29 && (raw[0] == 1.toByte() || raw[0] == 2.toByte())) {
            "Invalid encrypted record header"
        }
        val v = raw[0].toInt()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            if (v == 1) legacyKey() else master,
            GCMParameterSpec(128, raw.copyOfRange(1, 13))
        )
        if (v == 2) cipher.updateAAD(aad(id))
        val payload = cipher.doFinal(raw.copyOfRange(13, raw.size))
        val json = JSONObject(String(payload, Charsets.UTF_8))
        require(json.getString("id") == id)
        require(json.getInt("version") == v)
        return json
    }

    fun load(id: String): VaultItem {
        val json = decrypt(id)
        return VaultItem(
            id = id,
            kind = json.getString("kind"),
            title = json.getString("title"),
            body = json.getString("body"),
            mime = json.optString("mime", "application/octet-stream"),
            modified = json.getLong("modified"),
            starred = json.optBoolean("starred", false)
        )
    }

    fun migrateLegacy(): Int {
        var migrated = 0
        val files = dir.listFiles()?.filter { it.name.endsWith(".sg") } ?: emptyList()
        for (file in files) {
            if (file.inputStream().use { it.read() } == 1) {
                // Each record is atomically rewritten; interruption is safe to retry.
                save(load(file.name.removeSuffix(".sg")))
                migrated++
            }
        }
        // Invalidate the old key only when every original record has been
        // re-encrypted successfully. This is cryptographic erasure of the
        // v1 wrapping key; it does not guarantee filesystem secure deletion.
        if (files.none { it.inputStream().use { stream -> stream.read() } == 1 }) {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            if (ks.containsAlias(legacyAlias)) ks.deleteEntry(legacyAlias)
        }
        return migrated
    }

    fun list(): List<VaultItem> =
        dir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(".sg") }
            ?.map { load(it.name.removeSuffix(".sg")) }
            ?.sortedWith(compareByDescending<VaultItem> { it.starred }.thenByDescending { it.modified })
            ?: emptyList()

    fun count(): Int = dir.listFiles()?.count { it.name.endsWith(".sg") } ?: 0

    fun remove(id: String) {
        if (path(id).exists() && !path(id).delete()) error("Не удалось удалить запись")
    }

    fun toggleStar(item: VaultItem) =
        save(item.copy(starred = !item.starred, modified = System.currentTimeMillis()))

    fun note(id: String? = null, title: String, text: String, starred: Boolean = false) {
        val safeTitle = title.trim().ifBlank { "Без названия" }.take(200)
        require(text.length <= 1_000_000) { "Слишком длинная заметка" }
        save(VaultItem(id ?: UUID.randomUUID().toString(), "note", safeTitle, text,
            "text/markdown", System.currentTimeMillis(), starred))
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
