class APIGatewayException(Exception):
    """Base exception for API Gateway"""
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class AuthenticationException(APIGatewayException):
    """Raised when authentication fails"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, 401)

class AuthorizationException(APIGatewayException):
    """Raised when authorization fails"""
    def __init__(self, message: str = "Authorization failed"):
        super().__init__(message, 403)

class RateLimitException(APIGatewayException):
    """Raised when rate limit exceeded"""
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, 429)

class AttackDetectedException(APIGatewayException):
    """Raised when attack detected"""
    def __init__(self, message: str = "Attack detected"):
        super().__init__(message, 403)

class InvalidTokenException(AuthenticationException):
    """Raised when token is invalid"""
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)

class ExpiredTokenException(AuthenticationException):
    """Raised when token is expired"""
    def __init__(self, message: str = "Token expired"):
        super().__init__(message)
