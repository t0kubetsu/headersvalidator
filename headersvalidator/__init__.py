"""headersvalidator – HTTP headers configuration assessment library."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("headersvalidator")
except PackageNotFoundError:  # pragma: no cover – only when package not installed
    __version__ = "0.1.2"

# NullHandler so library users who have not configured logging
# do not see "No handler found" warnings (PEP 3118 / logging HOWTO).
import logging as _logging

_logging.getLogger("headersvalidator").addHandler(_logging.NullHandler())
del _logging

__all__ = ["__version__"]
