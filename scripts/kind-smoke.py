#!/usr/bin/env python3
"""Run the cdn API remediation test; see e2e.py for shared assertions."""
from e2e import main

if __name__ == '__main__':
    main(default_lane='cdn')
