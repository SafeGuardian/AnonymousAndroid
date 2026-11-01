package org.safeguardian.vault

import android.content.Context
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

/**
 * Streaming AES-256-GCM encryption with independent authenticated 64KiB chunks.
 *
 * Entire original filename/MIME/length/hash is stored inside encrypted VaultItem.
 * Blob filename is a random UUID. An on-disk body includes random salt, framed
 * ciphertext and an EOF marker. Chunk nonces are derived from a per-file HKDF-like
 * HMAC-derived key + unique monotonically increasing index; each per-file key is
 * different. The authenticated metadata supplies length and SHA-256 to catch
 * truncation and missing/duplicated frames.
 */
class EncryptedFileStore(
    context: Context,
    private val vault: VaultStore,
    key: ByteArray
) {
    private val dir = File(context.filesDir, "encrypted-files").apply { mkdirs() }
    private val master = key.copyOf()
    private val random = SecureRandom()

    private fun path(id: String): File {
        require(Regex("[a-f0-9-]{36}").matches(id))
        return File(dir, "$id.sgf")
    }

    private fun cipherKey(id: String, salt: ByteArray): SecretKeySpec {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(master, "HmacSHA256"))
        mac.update("SafeGuardian/SGF3/file-key".toByteArray())
        mac.update(salt)
        val derived = mac.doFinal(id.toByteArray())
        return SecretKeySpec(derived, "AES").also { derived.fill(0) }
    }

    private fun nonce(chunk: Long): ByteArray =
        ByteArray(12).apply {
            for (i in 0..7) this[4 + i] = (chunk ushr (56 - i * 8)).toByte()
        }

    private fun cipher(mode: Int, key: SecretKeySpec, id: String, counter: Long): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, key, GCMParameterSpec(128, nonce(counter)))
            updateAAD(("SafeGuardian/SGF3/$id/$counter").toByteArray())
        }

    fun import(name: String, mime: String, source: InputStream) {
        val id = UUID.randomUUID().toString()
        val salt = ByteArray(16).also(random::nextBytes)
        val key = cipherKey(id, salt)
        val temp = File(dir, "$id.tmp")
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        var index = 0L
        var committed = false
        try {
            DataOutputStream(temp.outputStream().buffered()).use { output ->
                output.write(byteArrayOf(83, 71, 70, 51))
                output.write(salt)
                val buffer = ByteArray(CHUNK)
                while (true) {
                    val count = source.read(buffer)
                    if (count == -1) break
                    if (count == 0) continue
                    size += count
                    require(size <= MAX_FILE) { "Файл больше 1 ГиБ" }
                    digest.update(buffer, 0, count)
                    val encrypted = cipher(Cipher.ENCRYPT_MODE, key, id, index++)
                        .doFinal(buffer, 0, count)
                    output.writeInt(encrypted.size)
                    output.write(encrypted)
                }
                output.writeInt(0)
                output.flush()
            }
            java.io.FileOutputStream(temp, true).use { it.fd.sync() }
            val final = path(id)
            try {
                Files.move(temp.toPath(), final.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temp.toPath(), final.toPath())
            }
            val meta = JSONObject().apply {
                put("format", "sgf3")
                put("size", size)
                put("sha256", Base64.encodeToString(digest.digest(), Base64.NO_WRAP))
            }
            vault.save(VaultItem(
                id, "file", name.take(240), meta.toString(),
                mime.take(150), System.currentTimeMillis()
            ))
            committed = true
        } finally {
            temp.delete()
            if (!committed) path(id).delete()
            salt.fill(0)
        }
    }

    fun export(item: VaultItem, destination: OutputStream) {
        require(item.kind == "file")
        val meta = runCatching { JSONObject(item.body) }.getOrNull()
        if (meta?.optString("format") != "sgf3") {
            // Data created by the legacy 0.1.0 app is a base64-encoded body
            // enclosed within an authenticated encrypted VaultItem.
            destination.write(Base64.decode(item.body, Base64.DEFAULT))
            return
        }
        val expectedSize = meta.getLong("size")
        require(expectedSize in 0..MAX_FILE)
        val expectedHash = Base64.decode(meta.getString("sha256"), Base64.DEFAULT)
        require(expectedHash.size == 32)
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        var index = 0L
        DataInputStream(path(item.id).inputStream().buffered()).use { input ->
            val header = ByteArray(4)
            input.readFully(header)
            require(header.contentEquals(byteArrayOf(83, 71, 70, 51))) { "Неверный формат файла" }
            val salt = ByteArray(16)
            input.readFully(salt)
            val key = cipherKey(item.id, salt)
            while (true) {
                val length = input.readInt()
                if (length == 0) break
                require(length in 17..CHUNK + 16 && index < MAX_FILE / CHUNK + 1) {
                    "Повреждённый фрейм файла"
                }
                val frame = ByteArray(length)
                input.readFully(frame)
                val bytes = cipher(Cipher.DECRYPT_MODE, key, item.id, index++).doFinal(frame)
                size += bytes.size
                require(size <= expectedSize) { "Неожиданный размер файла" }
                digest.update(bytes)
                destination.write(bytes)
                bytes.fill(0)
            }
            require(input.read() == -1) { "Лишние данные после конца файла" }
            require(size == expectedSize &&
                MessageDigest.isEqual(digest.digest(), expectedHash)) { "Проверка целостности не прошла" }
        }
    }

    fun remove(item: VaultItem) {
        require(item.kind == "file")
        vault.remove(item.id)
        path(item.id).delete()
    }

    fun clearSession() { master.fill(0) }

    companion object {
        const val CHUNK = 64 * 1024
        const val MAX_FILE = 1024L * 1024L * 1024L
    }
}
