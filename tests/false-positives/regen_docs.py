"""Regenerate the builtins list from the upstream manual.

Shape taken from pygments' lexer tooling, which scored HIGH download-exec on a
single stdlib call that only downloads a file.
"""
from urllib.request import urlretrieve

MANUAL_URL = "https://example.org/manual.tar.bz2"


def fetch():
    path, _headers = urlretrieve(MANUAL_URL)
    return path
