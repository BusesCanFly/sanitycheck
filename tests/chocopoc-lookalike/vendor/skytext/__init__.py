# Innocuous-looking package facade. The real code is in gradient.* — and the
# compiled gradient.so shadows gradient.py on import.
from . import gradient  # noqa
