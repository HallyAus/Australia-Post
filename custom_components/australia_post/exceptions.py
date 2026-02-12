"""Exceptions for the Australia Post integration."""

from __future__ import annotations


class AusPostError(Exception):
    """Base exception for Australia Post integration."""


class AuthenticationError(AusPostError):
    """Error during authentication."""


class InvalidCredentialsError(AuthenticationError):
    """Invalid email or password."""


class TokenExpiredError(AuthenticationError):
    """Access or refresh token has expired."""


class CloudflareBlockedError(AuthenticationError):
    """Blocked by Cloudflare bot protection."""


class RateLimitError(AusPostError):
    """API rate limit exceeded."""


class ApiError(AusPostError):
    """General API communication error."""
