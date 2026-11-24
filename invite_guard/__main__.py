"""Allow ``python -m invite_guard``."""
import sys

from .cli import main

sys.exit(main())
