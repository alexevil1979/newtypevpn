package com.shadowtunnel.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.shadowtunnel.protocol.*
import com.shadowtunnel.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.SecureRandom

/**
 * ShadowTunnel VPN Service для Android.
 *
 * Использует Android VpnService API для создания TUN-интерфейса
 * и маршрутизации трафика через зашифрованный туннель.
 */
class ShadowTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "ShadowTunnelVPN"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "shadowtunnel_vpn"

        const val ACTION_CONNECT = "com.shadowtunnel.CONNECT"
        const val ACTION_DISCONNECT = "com.shadowtunnel.DISCONNECT"

        const val EXTRA_SERVER_ADDR = "server_addr"
        const val EXTRA_SERVER_PORT = "server_port"

        var isRunning = false
            private set
        var tunnelIp: String? = null
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var socket: DatagramSocket? = null
    private var crypto = ShadowCrypto()
    private var packetBuilder: PacketBuilder? = null
    private var sessionId: ByteArray = ByteArray(16)
    private var sessionMagic: ByteArray = ByteArray(4)

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var serverAddr: String = ""
    private var serverPort: Int = 51820

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                serverAddr = intent.getStringExtra(EXTRA_SERVER_ADDR) ?: ""
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 51820)
                startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
                serviceScope.launch { connect() }
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    /**
     * Подключение к серверу.
     */
    private suspend fun connect() {
        try {
            Log.i(TAG, "Connecting to $serverAddr:$serverPort")

            // Создаём UDP-сокет
            socket = DatagramSocket().apply {
                soTimeout = 10000
            }
            protect(socket!!)

            // Генерируем ключи
            val identityKP = ShadowCrypto.generateIdentityKeyPair()
            val ephKP = ShadowCrypto.generateEphemeralKeyPair()

            // Инициализация сессии
            sessionId = ShadowCrypto.randomBytes(16)
            sessionMagic = ShadowCrypto.randomBytes(4)
            packetBuilder = PacketBuilder(sessionMagic, sessionId)

            // === Handshake ===
            val success = performHandshake(identityKP, ephKP)
            if (!success) {
                Log.e(TAG, "Handshake failed")
                updateNotification("Connection failed")
                return
            }

            // Настраиваем VPN-интерфейс
            setupVpnInterface()

            isRunning = true
            updateNotification("Connected to $serverAddr")
            Log.i(TAG, "Connected! Tunnel IP: $tunnelIp")

            // Запускаем циклы чтения/записи
            coroutineScope {
                launch { readFromTun() }
                launch { readFromSocket() }
                launch { keepaliveLoop() }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Connection error", e)
            updateNotification("Error: ${e.message}")
        }
    }

    /**
     * 3-way handshake.
     */
    private fun performHandshake(identityKP: KeyPair, ephKP: KeyPair): Boolean {
        val serverAddress = InetAddress.getByName(serverAddr)
        val ephPubRaw = ephKP.public.encoded.takeLast(32).toByteArray()
        val idPubRaw = identityKP.public.encoded.takeLast(32).toByteArray()

        // Подписываем ephemeral key
        val sig = crypto.sign(identityKP.private, ephPubRaw)
        val helloPayload = ephPubRaw + idPubRaw + sig

        val helloPkt = packetBuilder!!.buildHandshakePacket(
            PacketType.INIT_HELLO, helloPayload
        )
        helloPkt.hmac = ByteArray(32)

        // Отправляем INIT_HELLO
        val helloData = helloPkt.serialize()
        socket!!.send(DatagramPacket(helloData, helloData.size, serverAddress, serverPort))
        Log.d(TAG, "INIT_HELLO sent")

        // Получаем INIT_CHALLENGE
        val recvBuf = ByteArray(65535)
        val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
        try {
            socket!!.receive(recvPkt)
        } catch (e: SocketTimeoutException) {
            Log.e(TAG, "Timeout waiting for INIT_CHALLENGE")
            return false
        }

        val challengeData = recvBuf.copyOf(recvPkt.length)
        val challengePkt = ShadowPacket.deserialize(challengeData)

        if (challengePkt.packetType != PacketType.INIT_CHALLENGE) {
            Log.e(TAG, "Expected INIT_CHALLENGE, got ${challengePkt.packetType}")
            return false
        }

        // Обновляем session ID и magic от сервера
        sessionId = challengePkt.sessionId.copyOf()
        sessionMagic = challengePkt.magic.copyOf()
        packetBuilder = PacketBuilder(sessionMagic, sessionId)

        // Парсим ответ: server_ephemeral_pub(32) + nonce(12) + encrypted
        val payload = challengePkt.payload
        val serverEphPubRaw = payload.copyOfRange(0, 32)
        val encNonce = payload.copyOfRange(32, 44)
        val encryptedData = payload.copyOfRange(44, payload.size)

        // ECDH (simplified — in production use proper X25519 key import)
        // For now, set dummy session keys for the handshake flow
        // In a full implementation, we'd import the server's X25519 public key
        // and perform the actual ECDH exchange
        crypto.performECDH(ephKP.private, challengePkt.run {
            // Reconstruct server public key from raw bytes
            val keyFactory = java.security.KeyFactory.getInstance("X25519", "BC")
            val keySpec = java.security.spec.X509EncodedKeySpec(
                wrapX25519PublicKey(serverEphPubRaw)
            )
            keyFactory.generatePublic(keySpec)
        })

        // Дешифруем challenge
        val decrypted = crypto.decrypt(encNonce, encryptedData, sessionId)
        val challenge = decrypted.copyOfRange(0, 32)

        Log.d(TAG, "INIT_CHALLENGE received, sending response...")

        // INIT_RESPONSE
        val challengeSig = crypto.sign(identityKP.private, challenge)
        val responsePlain = challengeSig + challenge
        val (respNonce, respEnc) = crypto.encrypt(responsePlain, sessionId)

        val responsePkt = packetBuilder!!.buildHandshakePacket(
            PacketType.INIT_RESPONSE, respEnc, respNonce
        )
        val pktBytes = responsePkt.headerBytes() + responsePkt.payload + responsePkt.padding
        responsePkt.hmac = crypto.computeHmac(pktBytes)

        val respData = responsePkt.serialize()
        socket!!.send(DatagramPacket(respData, respData.size, serverAddress, serverPort))

        // Ожидаем INIT_CONFIRM
        try {
            socket!!.receive(recvPkt)
        } catch (e: SocketTimeoutException) {
            Log.e(TAG, "Timeout waiting for INIT_CONFIRM")
            return false
        }

        val confirmData = recvBuf.copyOf(recvPkt.length)
        val confirmPkt = ShadowPacket.deserialize(confirmData, sessionMagic)

        if (confirmPkt.packetType != PacketType.INIT_CONFIRM) {
            Log.e(TAG, "Expected INIT_CONFIRM")
            return false
        }

        // Дешифруем подтверждение
        val confirmDecrypted = crypto.decrypt(confirmPkt.nonce, confirmPkt.payload, sessionId)
        val errorCode = ByteBuffer.wrap(confirmDecrypted.copyOfRange(0, 4)).int

        if (errorCode != 0) {
            Log.e(TAG, "Server rejected: code $errorCode")
            return false
        }

        // Извлекаем tunnel IP
        if (confirmDecrypted.size > 4) {
            tunnelIp = String(confirmDecrypted.copyOfRange(4, confirmDecrypted.size))
        }

        return true
    }

    /**
     * Обёртка для X25519 raw public key в X509 формат.
     */
    private fun wrapX25519PublicKey(rawKey: ByteArray): ByteArray {
        // ASN.1 prefix for X25519 public key
        val prefix = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00
        )
        return prefix + rawKey
    }

    /**
     * Настройка VPN TUN-интерфейса.
     */
    private fun setupVpnInterface() {
        val builder = Builder()
            .setSession("ShadowTunnel")
            .setMtu(1400)
            .addAddress(tunnelIp ?: "10.8.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setBlocking(true)

        vpnInterface = builder.establish()
            ?: throw IllegalStateException("Failed to establish VPN interface")
    }

    /**
     * Читает IP-пакеты из TUN и отправляет через туннель.
     */
    private suspend fun readFromTun() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val buffer = ByteArray(32767)

        while (isRunning) {
            try {
                val length = input.read(buffer)
                if (length > 0) {
                    val ipPacket = buffer.copyOf(length)
                    sendEncrypted(ipPacket)
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "TUN read error", e)
                break
            }
        }
    }

    /**
     * Читает пакеты из UDP-сокета и записывает в TUN.
     */
    private suspend fun readFromSocket() {
        val recvBuf = ByteArray(65535)
        val output = vpnInterface?.let { FileOutputStream(it.fileDescriptor) } ?: return

        while (isRunning) {
            try {
                val pkt = DatagramPacket(recvBuf, recvBuf.size)
                socket!!.soTimeout = 1000
                socket!!.receive(pkt)

                val data = recvBuf.copyOf(pkt.length)
                handleReceivedPacket(data, output)
            } catch (e: SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Socket read error", e)
                break
            }
        }
    }

    /**
     * Обрабатывает полученный зашифрованный пакет.
     */
    private fun handleReceivedPacket(data: ByteArray, output: FileOutputStream) {
        try {
            val pkt = ShadowPacket.deserialize(data, sessionMagic)

            when (pkt.packetType) {
                PacketType.DATA -> {
                    // Проверяем HMAC
                    val dataForHmac = data.copyOfRange(0, data.size - ShadowPacket.HMAC_SIZE)
                    if (!crypto.verifyHmac(dataForHmac, pkt.hmac)) return

                    // Дешифруем
                    val plaintext = crypto.decrypt(pkt.nonce, pkt.payload, sessionId)
                    output.write(plaintext)
                }
                PacketType.KEEPALIVE -> {
                    Log.d(TAG, "Keepalive received")
                }
                PacketType.KEY_ROTATE_ACK -> {
                    Log.i(TAG, "Key rotation acknowledged")
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Packet handling error: ${e.message}")
        }
    }

    /**
     * Шифрует и отправляет IP-пакет через туннель.
     */
    private fun sendEncrypted(ipPacket: ByteArray) {
        try {
            val (nonce, encrypted) = crypto.encrypt(ipPacket, sessionId)
            val pkt = packetBuilder!!.buildDataPacket(encrypted, nonce)

            val pktBytes = pkt.headerBytes() + pkt.payload + pkt.padding
            pkt.hmac = crypto.computeHmac(pktBytes)

            val data = pkt.serialize()
            socket!!.send(
                DatagramPacket(
                    data, data.size,
                    InetAddress.getByName(serverAddr), serverPort
                )
            )
        } catch (e: Exception) {
            Log.e(TAG, "Send error", e)
        }
    }

    /**
     * Цикл keepalive.
     */
    private suspend fun keepaliveLoop() {
        while (isRunning) {
            delay(25000)
            try {
                val pkt = packetBuilder!!.buildKeepalive()
                val pktBytes = pkt.headerBytes() + pkt.payload + pkt.padding
                pkt.hmac = crypto.computeHmac(pktBytes)

                val data = pkt.serialize()
                socket!!.send(
                    DatagramPacket(
                        data, data.size,
                        InetAddress.getByName(serverAddr), serverPort
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "Keepalive error", e)
            }
        }
    }

    /**
     * Отключение.
     */
    private fun disconnect() {
        isRunning = false
        tunnelIp = null

        // Отправляем DISCONNECT
        try {
            packetBuilder?.let { pb ->
                val pkt = pb.buildDisconnect()
                val pktBytes = pkt.headerBytes() + pkt.payload + pkt.padding
                pkt.hmac = if (crypto.hasSessionKeys) crypto.computeHmac(pktBytes) else ByteArray(32)
                val data = pkt.serialize()
                socket?.send(
                    DatagramPacket(
                        data, data.size,
                        InetAddress.getByName(serverAddr), serverPort
                    )
                )
            }
        } catch (e: Exception) {
            Log.d(TAG, "Disconnect send error: ${e.message}")
        }

        serviceScope.cancel()
        vpnInterface?.close()
        vpnInterface = null
        socket?.close()
        socket = null
        crypto.clearKeys()

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        Log.i(TAG, "Disconnected")
    }

    // ── Notifications ────────────────────────────

    private fun createNotification(text: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "ShadowTunnel VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }

        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("ShadowTunnel")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createNotification(text))
    }
}
