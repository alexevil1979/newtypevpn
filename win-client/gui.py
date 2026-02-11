"""
ShadowTunnel Windows Client — PyQt6 GUI.

Современный интерфейс с:
- Кнопкой подключения/отключения
- Импортом конфигурации (файл / QR)
- Логами статуса
- Автоподключением
"""

import sys
import os
import time
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFileDialog, QGroupBox,
    QStatusBar, QMessageBox, QSystemTrayIcon, QMenu,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QAction

# Ensure imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from win_client.config import ClientConfig, get_config_dir
    from win_client.tunnel import ClientTunnel, ConnectionState
except ImportError:
    from config import ClientConfig, get_config_dir
    from tunnel import ClientTunnel, ConnectionState


class ConnectWorker(QThread):
    """Фоновый поток для подключения."""
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, tunnel: ClientTunnel):
        super().__init__()
        self._tunnel = tunnel

    def run(self):
        try:
            self._tunnel.connect()
        except Exception as e:
            self.error.emit(str(e))
        self.finished.emit()


class MainWindow(QMainWindow):
    """Главное окно приложения."""

    state_changed = pyqtSignal(object)
    log_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._config: ClientConfig = None
        self._tunnel: ClientTunnel = None
        self._worker: ConnectWorker = None

        self.state_changed.connect(self._on_state_change)
        self.log_received.connect(self._on_log)

        self._init_ui()
        self._load_saved_config()

    def _init_ui(self):
        """Инициализация интерфейса."""
        self.setWindowTitle("ShadowTunnel")
        self.setMinimumSize(520, 600)
        self.setStyleSheet(self._get_stylesheet())

        # Центральный виджет
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # ── Заголовок ─────────────────────────────
        header = QLabel("ShadowTunnel")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        subtitle = QLabel("Secure VPN Tunnel")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        # ── Статус ────────────────────────────────
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout(status_group)

        self._status_label = QLabel("Disconnected")
        self._status_label.setObjectName("statusLabel")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self._status_label)

        self._ip_label = QLabel("")
        self._ip_label.setObjectName("ipLabel")
        self._ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self._ip_label)

        layout.addWidget(status_group)

        # ── Кнопка подключения ────────────────────
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setObjectName("connectBtn")
        self._connect_btn.setMinimumHeight(52)
        self._connect_btn.clicked.connect(self._toggle_connection)
        layout.addWidget(self._connect_btn)

        # ── Конфигурация ──────────────────────────
        config_group = QGroupBox("Configuration")
        config_layout = QHBoxLayout(config_group)

        self._config_label = QLabel("No config loaded")
        self._config_label.setObjectName("configLabel")
        config_layout.addWidget(self._config_label, 1)

        import_btn = QPushButton("Import File")
        import_btn.clicked.connect(self._import_config_file)
        config_layout.addWidget(import_btn)

        layout.addWidget(config_group)

        # ── Логи ──────────────────────────────────
        log_group = QGroupBox("Logs")
        log_layout = QVBoxLayout(log_group)

        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setObjectName("logText")
        self._log_text.setMaximumHeight(200)
        log_layout.addWidget(self._log_text)

        layout.addWidget(log_group)

        layout.addStretch()

        # ── Статус бар ────────────────────────────
        self.statusBar().showMessage("Ready")

        # ── Таймер обновления статистики ──────────
        self._stats_timer = QTimer()
        self._stats_timer.timeout.connect(self._update_stats)
        self._stats_timer.start(2000)

    def _toggle_connection(self):
        """Переключение подключения."""
        if self._tunnel and self._tunnel.state == ConnectionState.CONNECTED:
            self._tunnel.disconnect()
        else:
            self._start_connection()

    def _start_connection(self):
        """Начинает подключение."""
        if not self._config or not self._config.is_valid():
            QMessageBox.warning(
                self, "Ошибка",
                "Конфигурация не загружена или невалидна.\n"
                "Импортируйте файл конфигурации."
            )
            return

        self._tunnel = ClientTunnel(
            self._config,
            on_state_change=lambda s: self.state_changed.emit(s),
            on_log=lambda m: self.log_received.emit(m),
        )

        self._worker = ConnectWorker(self._tunnel)
        self._worker.error.connect(lambda e: self._add_log(f"Error: {e}"))
        self._worker.start()

    def _import_config_file(self):
        """Импорт конфигурации из YAML-файла."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration",
            "", "YAML files (*.yaml *.yml);;All files (*)"
        )
        if not path:
            return

        try:
            self._config = ClientConfig.from_yaml(path)
            self._config_label.setText(
                f"{self._config.server_addr}:{self._config.server_port}"
            )
            self._add_log(f"Config loaded: {path}")
            # Сохраняем путь
            self._save_config_path(path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load config:\n{e}")

    def _load_saved_config(self):
        """Загружает последнюю использованную конфигурацию."""
        config_dir = get_config_dir()
        last_path = os.path.join(config_dir, "last_config.txt")
        if os.path.exists(last_path):
            with open(last_path, "r") as f:
                path = f.read().strip()
            if os.path.exists(path):
                try:
                    self._config = ClientConfig.from_yaml(path)
                    self._config_label.setText(
                        f"{self._config.server_addr}:{self._config.server_port}"
                    )
                except Exception:
                    pass

    def _save_config_path(self, path: str):
        """Сохраняет путь к последней конфигурации."""
        config_dir = get_config_dir()
        with open(os.path.join(config_dir, "last_config.txt"), "w") as f:
            f.write(path)

    def _on_state_change(self, state: ConnectionState):
        """Обработчик изменения состояния."""
        state_map = {
            ConnectionState.DISCONNECTED: ("Disconnected", "#ef4444", "Connect"),
            ConnectionState.CONNECTING: ("Connecting...", "#eab308", "Cancel"),
            ConnectionState.CONNECTED: ("Connected", "#22c55e", "Disconnect"),
            ConnectionState.RECONNECTING: ("Reconnecting...", "#f97316", "Cancel"),
            ConnectionState.ERROR: ("Error", "#ef4444", "Retry"),
        }
        text, color, btn_text = state_map.get(
            state, ("Unknown", "#888", "Connect")
        )
        self._status_label.setText(text)
        self._status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        self._connect_btn.setText(btn_text)

        if state == ConnectionState.CONNECTED and self._tunnel:
            ip = self._tunnel.stats.get("tunnel_ip", "")
            self._ip_label.setText(f"Tunnel IP: {ip}" if ip else "")
        else:
            self._ip_label.setText("")

    def _on_log(self, message: str):
        """Добавляет сообщение в лог."""
        self._add_log(message)

    def _add_log(self, message: str):
        """Добавляет строку в лог с временной меткой."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_text.append(f"[{timestamp}] {message}")
        # Автоскролл
        scrollbar = self._log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _update_stats(self):
        """Обновляет статистику в статус баре."""
        if self._tunnel and self._tunnel.state == ConnectionState.CONNECTED:
            stats = self._tunnel.stats
            sent = self._format_bytes(stats["bytes_sent"])
            recv = self._format_bytes(stats["bytes_received"])
            self.statusBar().showMessage(f"↑ {sent}  ↓ {recv}")

    @staticmethod
    def _format_bytes(b: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    def closeEvent(self, event):
        """Корректное закрытие."""
        if self._tunnel:
            self._tunnel.disconnect()
        event.accept()

    @staticmethod
    def _get_stylesheet() -> str:
        return """
        QMainWindow {
            background-color: #0f1117;
        }
        QWidget {
            color: #e4e6ef;
            font-family: 'Segoe UI', sans-serif;
        }
        #header {
            font-size: 28px;
            font-weight: bold;
            color: #4f7cff;
        }
        #subtitle {
            font-size: 14px;
            color: #9095a8;
        }
        #statusLabel {
            font-size: 20px;
            font-weight: bold;
            padding: 8px;
        }
        #ipLabel {
            font-size: 13px;
            color: #9095a8;
        }
        #configLabel {
            font-size: 13px;
            color: #9095a8;
        }
        QGroupBox {
            background-color: #1e2130;
            border: 1px solid #2a2d3e;
            border-radius: 10px;
            padding: 16px;
            padding-top: 28px;
            margin-top: 8px;
            font-weight: bold;
            color: #9095a8;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 16px;
            padding: 0 8px;
            color: #9095a8;
            font-size: 12px;
        }
        #connectBtn {
            background-color: #4f7cff;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            padding: 12px;
        }
        #connectBtn:hover {
            background-color: #3d6bf0;
        }
        #connectBtn:pressed {
            background-color: #2b59de;
        }
        QPushButton {
            background-color: #1e2130;
            color: #e4e6ef;
            border: 1px solid #2a2d3e;
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 13px;
        }
        QPushButton:hover {
            border-color: #4f7cff;
            background-color: #252838;
        }
        #logText {
            background-color: #0f1117;
            border: 1px solid #2a2d3e;
            border-radius: 8px;
            padding: 8px;
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 12px;
            color: #9095a8;
        }
        QStatusBar {
            background-color: #1a1d27;
            color: #9095a8;
            font-size: 12px;
            border-top: 1px solid #2a2d3e;
        }
        """
