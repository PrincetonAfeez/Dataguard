"""Shared DataGuard exceptions."""


class DataGuardError(Exception):
    """Base exception for friendly CLI failures."""


class InputError(DataGuardError):
    """Raised when input cannot be read or decoded."""


class ParseError(DataGuardError):
    """Raised when data cannot be parsed."""


class ValidationError(DataGuardError):
    """Raised when validation fails in a non-fatal way."""
