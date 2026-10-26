#!/usr/bin/env python3
"""Inspect and explicitly apply FileTrust network settings while stopped."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'core'))
from ft_network_config import cli
if __name__=='__main__': raise SystemExit(cli(ROOT))
