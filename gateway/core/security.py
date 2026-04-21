import hashlib
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
import jwt

# Use argon2 instead of bcrypt (no 72-byte limit)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

class SecurityManager:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using argon2"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, secret_key: Optional[str] = None) -> str:
        """Create JWT access token"""
        from gateway.config import settings
        
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, secret_key or settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str, secret_key: Optional[str] = None) -> Optional[dict]:
        """Verify JWT token"""
        from gateway.config import settings
        
        try:
            payload = jwt.decode(token, secret_key or settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except jwt.InvalidTokenError:
            return None
