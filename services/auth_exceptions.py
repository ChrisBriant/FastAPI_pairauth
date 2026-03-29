class TokenError(Exception):
    """Base class for token-related errors."""
    pass

class TokenNotFound(TokenError):
    """Token does not exist."""
    pass

class TokenUsed(TokenError):
    """Token has already been used."""
    pass

class TokenExpired(TokenError):
    """Token has expired."""
    pass

class DeviceAlreadyRegistered(Exception):
    """Device is already registered."""
    pass