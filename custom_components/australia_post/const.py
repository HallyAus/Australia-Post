"""Constants for the Australia Post MyPost Business integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "australia_post"

# Auth0 configuration (web login - email + password flow)
AUTH0_DOMAIN: Final = "welcome.auspost.com.au"
AUTH0_CLIENT_ID: Final = "MUFOPrh2WRpo7oBlCuQH5ppUGEGKJJzs"
AUTH0_AUDIENCE: Final = "https://digitalapi.auspost.com.au/high"
AUTH0_AUTHORIZE_URL: Final = f"https://{AUTH0_DOMAIN}/authorize"
AUTH0_TOKEN_URL: Final = f"https://{AUTH0_DOMAIN}/oauth/token"
AUTH0_LOGIN_URL: Final = f"https://{AUTH0_DOMAIN}/u/login"
AUTH0_REDIRECT_URI: Final = "https://auspost.com.au/mypost-business/shipping-and-tracking/"
AUTH0_SCOPES: Final = (
    "openid profile email offline_access "
    "https://scopes.auspost.com.au/auth/sending/v1/mpb-organisation "
    "https://scopes.auspost.com.au/auth/rrs-payment-recovery "
    "https://scopes.auspost.com.au/auth/lodgement/v1/sending"
)
AUTH0_CONNECTION: Final = "Username-Password-Authentication"

# Official Shipping & Tracking API Auth0 (client_credentials flow)
API_AUTH0_DOMAIN: Final = "welcome.api1.auspost.com.au"
API_AUTH0_TOKEN_URL: Final = f"https://{API_AUTH0_DOMAIN}/oauth/token"
API_AUTH0_AUDIENCE: Final = "https://digitalapi.auspost.com.au/shipping/v2"

# API configuration
API_BASE_URL: Final = "https://digitalapi.auspost.com.au"
API_PARTNER_ID: Final = "MPB-WEB"
API_ORG_TYPES: Final = "NCB"

# Authentication method
AUTH_METHOD_TOKEN: Final = "token"
AUTH_METHOD_API_KEY: Final = "api_key"
AUTH_METHOD_PASSWORD: Final = "password"

# Config entry data keys
CONF_AUTH_METHOD: Final = "auth_method"
CONF_EMAIL: Final = "email"
CONF_PARTNERS_TOKEN: Final = "partners_token"
CONF_CLIENT_ID: Final = "client_id"
CONF_CLIENT_SECRET: Final = "client_secret"
CONF_ACCESS_TOKEN: Final = "access_token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_ID_TOKEN: Final = "id_token"
CONF_EXPIRES_AT: Final = "expires_at"
CONF_ACCOUNT_NUMBER: Final = "account_number"
CONF_ORGANISATION_ID: Final = "organisation_id"
CONF_ORGANISATION_NAME: Final = "organisation_name"

# Update interval in minutes
DEFAULT_SCAN_INTERVAL: Final = 15

# Shipment statuses
ACTIVE_STATUSES: Final = frozenset(
    {
        "INITIATED",
        "TRACK_SHIPMENT",
        "IN_TRANSIT",
        "AWAITING_COLLECTION",
        "HELD_BY_COURIER",
        "POSSIBLE_DELAY",
        "UNSUCCESSFUL_PICKUP",
    }
)

TERMINAL_STATUSES: Final = frozenset(
    {
        "DELIVERED",
        "COMPLETED",
        "CANCELLED",
        "REFUNDED",
        "REFUND_IN_PROGRESS",
        "PARTIALLY_REFUNDED",
        "LOST",
        "CANNOT_BE_DELIVERED",
        "ARTICLE_DAMAGED",
    }
)

ALL_STATUSES: Final = ACTIVE_STATUSES | TERMINAL_STATUSES
