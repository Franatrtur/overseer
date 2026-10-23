#!/usr/bin/env python3
"""
Overseer: Syscall duplicate detector and profiler CLI runner.
"""

import os
import sys

# Ensure this workspace is on python sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from overseer.cli import main

if __name__ == "__main__":
    sys.exit(main())
