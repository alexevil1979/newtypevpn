"""
ShadowTunnel Tests — конфигурация pytest.
"""

import sys
import os
import pytest

# Добавляем корень проекта в PATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
