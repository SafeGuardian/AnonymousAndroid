package org.safeguardian.vault

import android.net.Uri
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 / RFC 4226 one-time codes. Secrets are held inside encrypted
 *  VaultItem bodies, never in device preferences or log output. */
data class TotpSpec(
    val secret: String,
    val issuer: String = "",
    val account: String = "",
    val digits: Int = 6,
    val period: Int = 30,
    val algorithm: String = "SHA1"
)

object PasswordTools {
    private val random = SecureRandom()
    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val NUMBERS = "23456789"
    private const val SYMBOLS = "!@#$%&*+-=?"

    fun generate(length: Int = 24, symbols: Boolean = true, numbers: Boolean = true): String {
        require(length in 12..128)
        val categories = mutableListOf(LOWER, UPPER)
        if (numbers) categories.add(NUMBERS)
        if (symbols) categories.add(SYMBOLS)
        val all = categories.joinToString("")
        val result = CharArray(length) { all[random.nextInt(all.length)] }
        categories.forEachIndexed { index, chars ->
            result[index] = chars[random.nextInt(chars.length)]
        }
        for (i in result.lastIndex downTo 1) {
            val j = random.nextInt(i + 1)
            val temp = result[i]
            result[i] = result[j]
            result[j] = temp
        }
        return String(result)
    }

    fun parseTotp(input: String): TotpSpec {
        val value = input.trim()
        if (!value.startsWith("otpauth://", ignoreCase = true)) {
            validateSecret(value)
            return TotpSpec(secret = value.replace(" ", "").uppercase(Locale.ROOT))
        }
        val uri = Uri.parse(value)
        require(uri.scheme.equals("otpauth", true) && uri.host.equals("totp", true)) {
            "Поддерживаются только TOTP-ссылки"
        }
        val secret = uri.getQueryParameter("secret")?.replace(" ", "")?.uppercase(Locale.ROOT)
            ?: error("В ссылке нет TOTP-секрета")
        validateSecret(secret)
        val digits = uri.getQueryParameter("digits")?.toIntOrNull() ?: 6
        val period = uri.getQueryParameter("period")?.toIntOrNull() ?: 30
        val alg = (uri.getQueryParameter("algorithm") ?: "SHA1").uppercase(Locale.ROOT)
        require(digits == 6 || digits == 8)
        require(period in 15..120)
        require(alg in setOf("SHA1", "SHA256", "SHA512"))
        val label = uri.pathSegments.joinToString("/")
        val issuer = uri.getQueryParameter("issuer") ?: label.substringBefore(":", "")
        val account = label.substringAfter(":", label)
        return TotpSpec(secret, issuer, account, digits, period, alg)
    }

    private fun validateSecret(value: String) {
        val normalized = value.replace(" ", "").trimEnd('=').uppercase(Locale.ROOT)
        require(normalized.length in 16..256 && normalized.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" }) {
            "Неверный Base32 TOTP-секрет"
        }
    }

    private fun decodeBase32(secret: String): ByteArray {
        val input = secret.uppercase(Locale.ROOT).replace(" ", "").trimEnd('=')
        validateSecret(input)
        val out = java.io.ByteArrayOutputStream()
        var bits = 0
        var buffered = 0
        for (char in input) {
            val symbol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char)
            require(symbol >= 0)
            buffered = (buffered shl 5) or symbol
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write((buffered shr bits) and 0xff)
                buffered = buffered and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }

    /** The time is injected for RFC test vectors, never read from a server. */
    fun totp(spec: TotpSpec, epochSeconds: Long = System.currentTimeMillis() / 1000L): String {
        require(spec.period in 15..120 && spec.digits in setOf(6, 8))
        require(spec.algorithm.uppercase(Locale.ROOT) in setOf("SHA1", "SHA256", "SHA512"))
        val key = decodeBase32(spec.secret)
        try {
            val counter = epochSeconds / spec.period
            val message = ByteArray(8) { idx -> (counter ushr (56 - 8 * idx)).toByte() }
            val mac = Mac.getInstance("Hmac" + spec.algorithm.uppercase(Locale.ROOT))
            mac.init(SecretKeySpec(key, mac.algorithm))
            val hash = mac.doFinal(message)
            val offset = (hash.last().toInt() and 0x0f)
            val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)
            val modulo = if (spec.digits == 6) 1_000_000 else 100_000_000
            return (binary % modulo).toString().padStart(spec.digits, '0')
        } finally {
            key.fill(0)
        }
    }

    fun remaining(spec: TotpSpec, epochSeconds: Long = System.currentTimeMillis() / 1000L): Int =
        (spec.period - epochSeconds % spec.period).toInt()
}
