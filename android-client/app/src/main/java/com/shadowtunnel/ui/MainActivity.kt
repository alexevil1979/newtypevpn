package com.shadowtunnel.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.shadowtunnel.R
import com.shadowtunnel.databinding.ActivityMainBinding
import com.shadowtunnel.vpn.ShadowTunnelVpnService
import org.yaml.snakeyaml.Yaml
import java.io.InputStream

/**
 * Главная Activity — UI клиента ShadowTunnel.
 *
 * Material Design интерфейс с:
 * - Кнопкой подключения
 * - Импортом конфигурации (файл)
 * - Отображением статуса
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val VPN_REQUEST_CODE = 100
        private const val FILE_PICK_CODE = 200
    }

    private lateinit var binding: ActivityMainBinding
    private var serverAddr: String = ""
    private var serverPort: Int = 51820
    private var isConnected = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    private fun setupUI() {
        binding.connectButton.setOnClickListener {
            if (isConnected) {
                disconnect()
            } else {
                startConnection()
            }
        }

        binding.importConfigButton.setOnClickListener {
            importConfig()
        }
    }

    /**
     * Начинает подключение — запрашивает разрешение VPN.
     */
    private fun startConnection() {
        if (serverAddr.isEmpty()) {
            Toast.makeText(this, "Импортируйте конфигурацию", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onVpnPermissionGranted()
        }
    }

    /**
     * VPN разрешение получено — запускаем сервис.
     */
    private fun onVpnPermissionGranted() {
        val intent = Intent(this, ShadowTunnelVpnService::class.java).apply {
            action = ShadowTunnelVpnService.ACTION_CONNECT
            putExtra(ShadowTunnelVpnService.EXTRA_SERVER_ADDR, serverAddr)
            putExtra(ShadowTunnelVpnService.EXTRA_SERVER_PORT, serverPort)
        }
        startForegroundService(intent)
        isConnected = true
        updateUI()
    }

    /**
     * Отключение.
     */
    private fun disconnect() {
        val intent = Intent(this, ShadowTunnelVpnService::class.java).apply {
            action = ShadowTunnelVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        isConnected = false
        updateUI()
    }

    /**
     * Импорт конфигурации из файла.
     */
    private fun importConfig() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, FILE_PICK_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            VPN_REQUEST_CODE -> {
                if (resultCode == Activity.RESULT_OK) {
                    onVpnPermissionGranted()
                } else {
                    Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
                }
            }
            FILE_PICK_CODE -> {
                if (resultCode == Activity.RESULT_OK) {
                    data?.data?.let { uri ->
                        try {
                            val input: InputStream? = contentResolver.openInputStream(uri)
                            val yaml = Yaml()
                            val config: Map<String, Any> = yaml.load(input)
                            parseConfig(config)
                            Toast.makeText(this, "Config loaded: $serverAddr:$serverPort", Toast.LENGTH_SHORT).show()
                            updateUI()
                        } catch (e: Exception) {
                            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseConfig(config: Map<String, Any>) {
        val server = config["server"] as? Map<String, Any> ?: return
        serverAddr = server["address"] as? String ?: ""
        serverPort = (server["port"] as? Number)?.toInt() ?: 51820
    }

    private fun updateUI() {
        val running = ShadowTunnelVpnService.isRunning
        isConnected = running

        binding.connectButton.text = if (running) "Disconnect" else "Connect"

        binding.statusText.text = when {
            running -> "Connected"
            serverAddr.isNotEmpty() -> "Ready to connect"
            else -> "Import configuration"
        }

        binding.serverInfo.text = if (serverAddr.isNotEmpty()) {
            "$serverAddr:$serverPort"
        } else {
            "No server configured"
        }

        val tunnelIp = ShadowTunnelVpnService.tunnelIp
        binding.tunnelIpText.text = tunnelIp ?: ""
    }
}
