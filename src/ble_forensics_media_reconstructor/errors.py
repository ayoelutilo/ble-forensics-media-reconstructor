"""Project exceptions."""


class ParseError(ValueError):
    """Raised when a capture file cannot be parsed."""


class ATTDecodeError(ValueError):
    """Raised when ATT payload decoding fails."""
