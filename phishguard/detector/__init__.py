"""Offline URL analysis: parsing, feature extraction, rules and verdicts.

This package has no dependency on Flask or the database, so it can be used
from scripts (for example the ML training pipeline) and tested in isolation.
"""

from phishguard import __version__

#: Version of the detection logic, recorded on every scan.
DETECTOR_VERSION = f"detector-{__version__}"
