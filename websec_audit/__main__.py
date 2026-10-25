"""Entry point for `python -m websec_audit`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
