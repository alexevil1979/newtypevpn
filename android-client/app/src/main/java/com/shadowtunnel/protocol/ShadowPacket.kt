package com.shadowtunnel.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * ShadowTunnel — формат пакетов для Android.
 *
 * Структура:
 * Magic(4) + Type(1) + SessionID(16) + Timestamp(8) + Sequence(4) +
 * Nonce(12) + PayloadLength(2) + Payload(var) + Padding(var) + HMAC(32)
 */
object PacketType {
    const val INIT_HELLO: Byte = 0x01
    const val INIT_CHALLENGE: Byte = 0x02
    const val INIT_RESPONSE: Byte = 0x03
    const val INIT_CONFIRM: Byte = 0x04
    const val DATA: Byte = 0x10
    const val KEEPALIVE: Byte = 0x20
    const val KEY_ROTATE: Byte = 0x30
    const val KEY_ROTATE_ACK: Byte = 0x31
    const val DISCONNECT: Byte = 0xFF.toByte()
}

data class ShadowPacket(
    val magic: ByteArray = ByteArray(4),
    val packetType: Byte = PacketType.DATA,
    val sessionId: ByteArray = ByteArray(16),
    val timestamp: Long = System.currentTimeMillis(),
    val sequence: Int = 0,
    val nonce: ByteArray = ByteArray(12),
    val payload: ByteArray = ByteArray(0),
    val padding: ByteArray = ByteArray(0),
    var hmac: ByteArray = ByteArray(0)
) {
    companion object {
        const val HEADER_SIZE = 47  // 4+1+16+8+4+12+2
        const val HMAC_SIZE = 32

        /**
         * Десериализует пакет из сырых байтов.
         */
        fun deserialize(data: ByteArray, expectedMagic: ByteArray? = null): ShadowPacket {
            require(data.size >= HEADER_SIZE + HMAC_SIZE) {
                "Packet too small: ${data.size}"
            }

            val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

            val magic = ByteArray(4).also { buf.get(it) }
            val type = buf.get()
            val sessionId = ByteArray(16).also { buf.get(it) }
            val timestamp = buf.getLong()
            val sequence = buf.getInt()
            val nonce = ByteArray(12).also { buf.get(it) }
            val payloadLength = buf.getShort().toInt() and 0xFFFF

            // Validate magic
            expectedMagic?.let { expected ->
                require(magic.contentEquals(expected)) { "Magic mismatch" }
            }

            val payload = ByteArray(payloadLength).also { buf.get(it) }

            // HMAC is last 32 bytes
            val hmac = data.copyOfRange(data.size - HMAC_SIZE, data.size)

            // Padding is between payload and HMAC
            val paddingStart = HEADER_SIZE + payloadLength
            val paddingEnd = data.size - HMAC_SIZE
            val padding = if (paddingEnd > paddingStart) {
                data.copyOfRange(paddingStart, paddingEnd)
            } else {
                ByteArray(0)
            }

            return ShadowPacket(
                magic = magic,
                packetType = type,
                sessionId = sessionId,
                timestamp = timestamp,
                sequence = sequence,
                nonce = nonce,
                payload = payload,
                padding = padding,
                hmac = hmac
            )
        }
    }

    /**
     * Сериализует заголовок пакета.
     */
    fun headerBytes(): ByteArray {
        val buf = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
        buf.put(magic)
        buf.put(packetType)
        buf.put(sessionId)
        buf.putLong(timestamp)
        buf.putInt(sequence)
        buf.put(nonce)
        buf.putShort(payload.size.toShort())
        return buf.array()
    }

    /**
     * Сериализует полный пакет.
     */
    fun serialize(): ByteArray {
        val header = headerBytes()
        val result = ByteArray(header.size + payload.size + padding.size + hmac.size)
        System.arraycopy(header, 0, result, 0, header.size)
        System.arraycopy(payload, 0, result, header.size, payload.size)
        System.arraycopy(padding, 0, result, header.size + payload.size, padding.size)
        System.arraycopy(hmac, 0, result, result.size - hmac.size, hmac.size)
        return result
    }
}

/**
 * Билдер пакетов с управлением sequence number.
 */
class PacketBuilder(
    private val sessionMagic: ByteArray,
    private val sessionId: ByteArray,
    private val obfuscation: String = "random_padding"
) {
    private var sequence = 0

    private fun nextSequence(): Int {
        val seq = sequence
        sequence = (sequence + 1) and 0x7FFFFFFF
        return seq
    }

    fun buildDataPacket(encryptedPayload: ByteArray, nonce: ByteArray): ShadowPacket {
        return ShadowPacket(
            magic = sessionMagic,
            packetType = PacketType.DATA,
            sessionId = sessionId,
            sequence = nextSequence(),
            nonce = nonce,
            payload = encryptedPayload,
            padding = generatePadding()
        )
    }

    fun buildHandshakePacket(type: Byte, payload: ByteArray, nonce: ByteArray = ByteArray(12)): ShadowPacket {
        return ShadowPacket(
            magic = sessionMagic,
            packetType = type,
            sessionId = sessionId,
            sequence = nextSequence(),
            nonce = nonce,
            payload = payload
        )
    }

    fun buildKeepalive(): ShadowPacket {
        return ShadowPacket(
            magic = sessionMagic,
            packetType = PacketType.KEEPALIVE,
            sessionId = sessionId,
            sequence = nextSequence()
        )
    }

    fun buildDisconnect(): ShadowPacket {
        return ShadowPacket(
            magic = sessionMagic,
            packetType = PacketType.DISCONNECT,
            sessionId = sessionId,
            sequence = nextSequence()
        )
    }

    private fun generatePadding(): ByteArray {
        return when (obfuscation) {
            "random_padding" -> {
                val len = (Math.random() * 256).toInt()
                ShadowCrypto.randomBytes(len)
            }
            else -> ByteArray(0)
        }
    }
}
