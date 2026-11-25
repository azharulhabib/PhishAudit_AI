"""Research-only URL feature contract 1.0.0 prototype. No network/application imports."""

from .extractor import Extractor, ConfigurationError

__all__ = ["Extractor", "ConfigurationError"]
