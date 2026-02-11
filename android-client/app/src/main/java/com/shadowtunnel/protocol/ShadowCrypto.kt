package com.shadowtunnel.protocol

import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * ShadowTunnel — криптографический движок для Android.
 *
 * Реализует:
 * - AES-256-GCM шифрование
 * - X25519 ECDH обмен ключами
 * - Ed25519 подписи
 * - HMAC-SHA256
 * - HKDF деривация ключей
 */
class ShadowCrypto {

    companion object {
        const val AES_KEY_SIZE = 32
        const val NONCE_SIZE = 12
        const val HMAC_SIZE = 32
        const val GCM_TAG_BITS = 128

        init {
            Security.addProvider(BouncyCastleProvider())
        }

        /**
         * Генерирует пару ключей Ed25519 для аутентификации.
         */
        fun generateIdentityKeyPair(): KeyPair {
            val kpg = KeyPairGenerator.getInstance("Ed25519", "BC")
            return kpg.generateKeyPair()
        }

        /**
         * Генерирует эфемерную пару ключей X25519 для ECDH.
         */
        fun generateEphemeralKeyPair(): KeyPair {
            val kpg = KeyPairGenerator.getInstance("X25519", "BC")
            return kpg.generateKeyPair()
        }

        /**
         * Генерирует случайный challenge.
         */
        fun generateChallenge(size: Int = 32): ByteArray {
            return SecureRandom().let { sr ->
                ByteArray(size).also { sr.nextBytes(it) }
            }
        }

        /**
         * Генерирует случайные байты.
         */
        fun randomBytes(size: Int): ByteArray {
            return SecureRandom().let { sr ->
                ByteArray(size).also { sr.nextBytes(it) }
            }
        }
    }

    private var sessionKey: ByteArray? = null
    private var hmacKey: ByteArray? = null

    val hasSessionKeys: Boolean
        get() = sessionKey != null && hmacKey != null

    /**
     * Выполняет X25519 ECDH и деривирует сессионные ключи.
     */
    fun performECDH(ourPrivate: PrivateKey, theirPublic: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519", "BC")
        ka.init(ourPrivate)
        ka.doPhase(theirPublic, true)
        val sharedSecret = ka.generateSecret()

        // HKDF derive (simplified — using HMAC-based extract-and-expand)
        val derived = hkdfDerive(
            sharedSecret,
            salt = null,
            info = "ShadowTunnel-v1-session-keys".toByteArray(),
            length = AES_KEY_SIZE + HMAC_SIZE
        )

        sessionKey = derived.copyOfRange(0, AES_KEY_SIZE)
        hmacKey = derived.copyOfRange(AES_KEY_SIZE, AES_KEY_SIZE + HMAC_SIZE)

        return derived
    }

    /**
     * Устанавливает сессионные ключи напрямую.
     */
    fun setSessionKeys(aesKey: ByteArray, hmacKey: ByteArray) {
        require(aesKey.size == AES_KEY_SIZE) { "Invalid AES key size" }
        require(hmacKey.size == HMAC_SIZE) { "Invalid HMAC key size" }
        this.sessionKey = aesKey.copyOf()
        this.hmacKey = hmacKey.copyOf()
    }

    /**
     * Шифрует данные AES-256-GCM.
     * @return Pair(nonce, ciphertext)
     */
    fun encrypt(plaintext: ByteArray, aad: ByteArray = ByteArray(0)): Pair<ByteArray, ByteArray> {
        val key = sessionKey ?: throw SecurityException("Session keys not set")
        val nonce = randomBytes(NONCE_SIZE)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        
        return Pair(nonce, ciphertext)
    }

    /**
     * Дешифрует данные AES-256-GCM.
     */
    fun decrypt(nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val key = sessionKey ?: throw SecurityException("Session keys not set")
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    /**
     * Подписывает данные Ed25519.
     */
    fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
        val sig = Signature.getInstance("Ed25519", "BC")
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    /**
     * Проверяет подпись Ed25519.
     */
    fun verifySignature(publicKey: PublicKey, signature: ByteArray, data: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance("Ed25519", "BC")
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Вычисляет HMAC-SHA256.
     */
    fun computeHmac(data: ByteArray): ByteArray {
        val key = hmacKey ?: throw SecurityException("HMAC key not set")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * Проверяет HMAC-SHA256.
     */
    fun verifyHmac(data: ByteArray, expectedHmac: ByteArray): Boolean {
        val computed = computeHmac(data)
        return MessageDigest.isEqual(computed, expectedHmac)
    }

    /**
     * Деривирует новые ключи при ротации.
     */
    fun deriveRotationKeys(currentKey: ByteArray, counter: Int): ByteArray {
        val info = "ShadowTunnel-v1-key-rotation-".toByteArray() +
                counter.toBigEndianBytes()
        val entropy = randomBytes(32)
        val derived = hkdfDerive(entropy, salt = currentKey, info = info, length = AES_KEY_SIZE + HMAC_SIZE)
        sessionKey = derived.copyOfRange(0, AES_KEY_SIZE)
        hmacKey = derived.copyOfRange(AES_KEY_SIZE, AES_KEY_SIZE + HMAC_SIZE)
        return derived
    }

    /**
     * Очищает ключи из памяти.
     */
    fun clearKeys() {
        sessionKey?.fill(0)
        hmacKey?.fill(0)
        sessionKey = null
        hmacKey = null
    }

    // ── HKDF (RFC 5869) ─────────────────────────────

    private fun hkdfDerive(
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        length: Int
    ): ByteArray {
        // Extract
        val prk = hmacSha256(salt ?: ByteArray(32), ikm)
        
        // Expand
        val n = (length + 31) / 32
        var t = ByteArray(0)
        val okm = ByteArray(length)
        var offset = 0
        
        for (i in 1..n) {
            val input = t + info + byteArrayOf(i.toByte())
            t = hmacSha256(prk, input)
            val copyLen = minOf(32, length - offset)
            System.arraycopy(t, 0, okm, offset, copyLen)
            offset += copyLen
        }
        
        return okm
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

fun Int.toBigEndianBytes(): ByteArray {
    return byteArrayOf(
        (this shr 24).toByte(),
        (this shr 16).toByte(),
        (this shr 8).toByte(),
        this.toByte()
    )
}
