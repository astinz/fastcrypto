package uniffi.fastcrypto_uniffi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FastCryptoTest {
    @Test
    fun testHash() {
        val data = "Hello World".encodeToByteArray()
        val digest = hash(data, HashType.SHA256)
        assertEquals(32, digest.size)

        // "Hello World" sha256 hex: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
        val expectedHex = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        assertEquals(expectedHex, hexEncode(digest).lowercase())
    }

    @Test
    fun testHexDecode() {
        val hex = "a591a6d4"
        val bytes = hexDecode(hex)
        assertEquals(4, bytes.size)
        assertEquals(0xa5.toByte(), bytes[0])
        assertEquals(0x91.toByte(), bytes[1])
    }

    @Test
    fun testEd25519() {
        val keyPair = Ed25519KeyPairWrapper.generate()
        val msg = "Hello Ed25519".encodeToByteArray()
        val sig = keyPair.sign(msg)
        assertEquals(64, sig.size)

        val valid = keyPair.verify(msg, sig)
        assertTrue(valid)
    }

    @Test
    fun testSecp256k1() {
        val keyPair = Secp256k1KeyPairWrapper.generate()
        val msg = "Hello Secp256k1".encodeToByteArray()
        val sig = keyPair.sign(msg)
        // Secp256k1 signature length can vary slightly depending on encoding but usually 64-65 or DER encoded
        // FastCrypto seems to use a fixed length or compact format
        // Checking verify instead of exact length first

        val valid = keyPair.verify(msg, sig)
        assertTrue(valid)
    }

    @Test
    fun testSecp256r1() {
        val keyPair = Secp256r1KeyPairWrapper.generate()
        val msg = "Hello Secp256r1".encodeToByteArray()
        val sig = keyPair.sign(msg)
        val valid = keyPair.verify(msg, sig)
        assertTrue(valid)
    }

    @Test
    fun testBLS12381() {
        val keyPair = Bls12381KeyPairWrapper.generate()
        val msg = "Hello BLS".encodeToByteArray()
        val sig = keyPair.sign(msg)
        val valid = keyPair.verify(msg, sig)
        assertTrue(valid)
    }
}
