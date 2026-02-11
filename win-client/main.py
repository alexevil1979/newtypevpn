#!/usr/bin/env python3
"""
ShadowTunnel Windows Client — точка входа.

Запуск:
    python -m win_client.main

Сборка:
    pyinstaller win-client/main.py --onefile --windowed --name ShadowTunnel
"""

import sys
import os
import logging

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import QApplication

try:
    from win_client.gui import MainWindow
except ImportError:
    from gui import MainWindow


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    app.setApplicationName("ShadowTunnel")
    app.setOrganizationName("ShadowTunnel")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
