import os
import sys

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "TA-epss", "bin")
LIB_DIR = os.path.join(BIN_DIR, "lib")
sys.path.insert(0, BIN_DIR)
sys.path.insert(0, LIB_DIR)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
