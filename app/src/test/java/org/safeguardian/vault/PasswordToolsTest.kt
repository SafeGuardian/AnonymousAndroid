package org.safeguardian.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordToolsTest {
    @Test fun rfc6238Sha1Example() {
        val spec = TotpSpec("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits = 8)
        assertEquals("94287082", PasswordTools.totp(spec, 59))
        assertEquals("07081804", PasswordTools.totp(spec, 1111111109L))
    }

    @Test fun generatorLengthsAndAlphabet() {
        repeat(30) {
            val value = PasswordTools.generate(32)
            assertEquals(32, value.length)
            assertTrue(value.any { it.isUpperCase() })
            assertTrue(value.any { it.isLowerCase() })
            assertTrue(value.any { it.isDigit() })
            assertTrue(value.any { it in "!@#$%&*+-=?" })
        }
    }

    @Test fun generatorMinimumLength() {
        assertEquals(12, PasswordTools.generate(12).length)
    }
}
