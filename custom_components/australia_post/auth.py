"""Auth0 authentication handler for Australia Post MyPost Business."""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import json
import logging
import re
import secrets
import time
import urllib.parse
from html import unescape as html_unescape
from typing import Any, Callable, Coroutine

import aiohttp

from .const import (
    API_AUTH0_AUDIENCE,
    API_AUTH0_TOKEN_URL,
    AUTH0_AUDIENCE,
    AUTH0_AUTHORIZE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CONNECTION,
    AUTH0_DOMAIN,
    AUTH0_LOGIN_URL,
    AUTH0_REDIRECT_URI,
    AUTH0_SCOPES,
    AUTH0_TOKEN_URL,
)
from .exceptions import (
    AuthenticationError,
    CloudflareBlockedError,
    InvalidCredentialsError,
    RateLimitError,
    TokenExpiredError,
)

_LOGGER = logging.getLogger(__name__)

# Base64-encoded Auth0 client metadata: {"name":"auth0-spa-js","version":"2.1.3"}
_AUTH0_CLIENT_INFO = base64.b64encode(
    json.dumps({"name": "auth0-spa-js", "version": "2.1.3"}).encode()
).decode()

# User-Agent to use for auth requests
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36"
)

# Comprehensive browser headers to reduce bot-detection triggers
_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": _USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-AU,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Sec-Ch-Ua": '"Chromium";v="144", "Not A(Brand";v="99", "Google Chrome";v="144"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}

# Headers for top-level navigation (GET /authorize)
_NAV_HEADERS: dict[str, str] = {
    **_BROWSER_HEADERS,
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# Headers for same-origin form POST (POST /u/login)
_FORM_POST_HEADERS: dict[str, str] = {
    **_BROWSER_HEADERS,
    "Content-Type": "application/x-www-form-urlencoded",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
}

# Markers that identify a Cloudflare challenge page
_CF_MARKERS = (
    "Please enable JS and disable any ad blocker",
    "data-cfasync",
    "cf-browser-verification",
    "challenges.cloudflare.com",
    "cf_chl_opt",
    "just a moment",
)


def _mask_token(token: str | None) -> str:
    """Mask a token for safe logging."""
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}...{token[-4:]}"


class AusPostAuth:
    """Handle Auth0 authentication for Australia Post MyPost Business.

    Implements the Auth0 New Universal Login flow programmatically to obtain
    OAuth2 tokens using email + password credentials. Tokens are refreshed
    automatically using the refresh_token grant.
    """

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Initialise the auth handler.

        Args:
            session: aiohttp session for making API calls (token refresh).
                     A separate session with cookies is created for the login flow.
        """
        self._session = session
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._id_token: str | None = None
        self._expires_at: float = 0.0
        # Partners token (static, no expiry)
        self._partners_token: str | None = None
        # Client credentials for official API (client_credentials grant)
        self._api_client_id: str | None = None
        self._api_client_secret: str | None = None
        self._on_token_refresh: (
            Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | None
        ) = None

    def set_token_refresh_callback(
        self,
        callback: Callable[[dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Set a callback to be called when tokens are refreshed."""
        self._on_token_refresh = callback

    def set_partners_token(self, token: str) -> None:
        """Store a Partners token as a static bearer credential.

        Partners tokens are generated from the MyPost Business dashboard
        under Business Details > eCommerce Partners. They do not expire
        unless the user disconnects the partner.
        """
        self._partners_token = token
        # Also set as access_token so it's returned by async_get_access_token
        self._access_token = token
        # Never expires (set far future)
        self._expires_at = float("inf")

    def set_client_credentials(
        self, client_id: str, client_secret: str
    ) -> None:
        """Store API client credentials for automatic token refresh.

        When set, the auth handler will use the client_credentials grant
        to obtain new access tokens when the current one expires, instead
        of requiring a refresh_token.
        """
        self._api_client_id = client_id
        self._api_client_secret = client_secret

    def restore_tokens(
        self,
        access_token: str,
        refresh_token: str,
        expires_at: float,
        id_token: str = "",
    ) -> None:
        """Restore tokens from stored config entry data."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = expires_at
        self._id_token = id_token

    @property
    def access_token(self) -> str | None:
        """Return the current access token."""
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        """Return the current refresh token."""
        return self._refresh_token

    @property
    def expires_at(self) -> float:
        """Return the token expiry timestamp."""
        return self._expires_at

    async def async_get_access_token(self) -> str:
        """Return a valid access token, refreshing if necessary.

        Supports three auth strategies:
        1. Partners token (static, never expires)
        2. refresh_token grant (email+password login)
        3. client_credentials grant (API key login - re-requests a new token)

        Raises:
            TokenExpiredError: If no valid token and no refresh method available.
        """
        # Partners token never expires
        if self._partners_token:
            return self._partners_token

        if self._access_token and time.time() < self._expires_at - 60:
            return self._access_token

        if self._refresh_token:
            _LOGGER.debug("Access token expired, refreshing via refresh_token")
            tokens = await self.async_refresh_token(self._refresh_token)
            self._update_tokens(tokens)
            if self._on_token_refresh:
                await self._on_token_refresh(tokens)
            return self._access_token  # type: ignore[return-value]

        if self._api_client_id and self._api_client_secret:
            _LOGGER.debug(
                "Access token expired, refreshing via client_credentials"
            )
            tokens = await self.async_login_client_credentials(
                self._api_client_id, self._api_client_secret
            )
            if self._on_token_refresh:
                await self._on_token_refresh(tokens)
            return self._access_token  # type: ignore[return-value]

        raise TokenExpiredError("No valid token and no refresh method available")

    # ------------------------------------------------------------------
    # Official API: client_credentials grant
    # ------------------------------------------------------------------

    async def async_login_client_credentials(
        self, client_id: str, client_secret: str
    ) -> dict[str, Any]:
        """Authenticate using the official Shipping & Tracking API credentials.

        Uses OAuth2 client_credentials grant against the official API Auth0
        domain (welcome.api1.auspost.com.au) which does NOT have Cloudflare
        bot protection.

        Args:
            client_id: API client ID from Australia Post Developer Centre.
            client_secret: API client secret.

        Returns:
            Dict with access_token, expires_in, expires_at, token_type.
        """
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": API_AUTH0_AUDIENCE,
            "grant_type": "client_credentials",
        }

        _LOGGER.debug("AusPost API: requesting token via client_credentials")

        async with self._session.post(
            API_AUTH0_TOKEN_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
        ) as resp:
            if resp.status == 401:
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost API client_credentials: HTTP 401: %s",
                    body[:200],
                )
                raise InvalidCredentialsError(
                    "Invalid API client_id or client_secret"
                )
            if resp.status == 403:
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost API client_credentials: HTTP 403: %s",
                    body[:200],
                )
                raise InvalidCredentialsError(
                    "Access denied - check API client credentials"
                )
            if resp.status == 429:
                raise RateLimitError("API rate limit exceeded")
            if resp.status != 200:
                body = await resp.text()
                _LOGGER.error(
                    "AusPost API client_credentials: HTTP %s: %s",
                    resp.status,
                    body[:200],
                )
                raise AuthenticationError(
                    f"API token request failed (HTTP {resp.status})"
                )
            data = await resp.json()

        data["expires_at"] = time.time() + data.get("expires_in", 14400)
        # client_credentials doesn't return refresh_token
        data.setdefault("refresh_token", "")

        _LOGGER.debug(
            "AusPost API: token obtained, expires_in=%s",
            data.get("expires_in"),
        )

        self._update_tokens(data)
        return data

    @staticmethod
    def generate_authorize_url() -> tuple[str, str]:
        """Generate an OAuth2 authorize URL with PKCE for browser login.

        The user opens this URL in their browser, logs in, and pastes
        the redirect URL back. This bypasses all bot protection because
        the user's real browser handles the login page.

        Returns:
            Tuple of (authorize_url, code_verifier).
        """
        code_verifier, code_challenge = AusPostAuth._generate_pkce()
        nonce = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        params = urllib.parse.urlencode(
            {
                "client_id": AUTH0_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": AUTH0_REDIRECT_URI,
                "scope": AUTH0_SCOPES,
                "audience": AUTH0_AUDIENCE,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "nonce": nonce,
                "auth0Client": _AUTH0_CLIENT_INFO,
            }
        )
        return f"{AUTH0_AUTHORIZE_URL}?{params}", code_verifier

    async def async_exchange_code(
        self, code: str, code_verifier: str
    ) -> dict[str, Any]:
        """Exchange an authorization code for tokens using PKCE.

        Args:
            code: The authorization code from the callback URL.
            code_verifier: The PKCE code verifier from generate_authorize_url().

        Returns:
            Dict with access_token, refresh_token, id_token, expires_at.
        """
        payload = {
            "grant_type": "authorization_code",
            "client_id": AUTH0_CLIENT_ID,
            "code_verifier": code_verifier,
            "code": code,
            "redirect_uri": AUTH0_REDIRECT_URI,
        }
        async with self._session.post(
            AUTH0_TOKEN_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
            },
        ) as resp:
            if resp.status == 401:
                raise InvalidCredentialsError(
                    "Authorization code expired or invalid. Please try again."
                )
            if resp.status == 403:
                raise AuthenticationError(
                    "Access denied during token exchange"
                )
            if resp.status != 200:
                text = await resp.text()
                raise AuthenticationError(
                    f"Token exchange failed (HTTP {resp.status}): {text[:200]}"
                )
            data = await resp.json()

        data["expires_at"] = time.time() + data.get("expires_in", 1800)
        self._update_tokens(data)
        return data

    async def async_login(self, email: str, password: str) -> dict[str, Any]:
        """Perform complete Auth0 login and return token dict.

        Tries multiple auth strategies in order of reliability:
        1. ROPC (Resource Owner Password Credentials) - simplest
        2. password-realm grant - extended ROPC with connection/realm
        3. Cross-origin authentication (/co/authenticate) - API-based, no
           browser simulation needed, bypasses Cloudflare bot protection
        4. Browser simulation with curl_cffi (Chrome TLS impersonation)

        Args:
            email: User's email address.
            password: User's password.

        Returns:
            Dict with access_token, refresh_token, id_token, expires_in, expires_at.

        Raises:
            InvalidCredentialsError: If credentials are wrong.
            RateLimitError: If rate limited by Auth0.
            AuthenticationError: For other auth failures.
        """
        # 1. Try ROPC first (simplest, but may not be enabled for SPA clients)
        ropc_result = await self._try_ropc_login(email, password)
        if ropc_result is not None:
            _LOGGER.warning("AusPost login: ROPC succeeded")
            self._update_tokens(ropc_result)
            return ropc_result

        _LOGGER.warning("AusPost login: ROPC not available")

        # 2. Try password-realm grant (ROPC variant with realm/connection)
        realm_result = await self._try_password_realm(email, password)
        if realm_result is not None:
            _LOGGER.warning("AusPost login: password-realm succeeded")
            self._update_tokens(realm_result)
            return realm_result

        _LOGGER.warning("AusPost login: password-realm not available")

        # 3. Try Auth0 cross-origin authentication (bypasses Cloudflare)
        co_result = await self._try_co_authenticate(email, password)
        if co_result is not None:
            _LOGGER.warning("AusPost login: cross-origin auth succeeded")
            self._update_tokens(co_result)
            return co_result

        _LOGGER.warning(
            "AusPost login: cross-origin auth not available, "
            "falling back to browser simulation"
        )

        # 4. Fall back to browser simulation
        return await self._browser_simulation_login(email, password)

    async def _try_ropc_login(
        self, email: str, password: str
    ) -> dict[str, Any] | None:
        """Attempt Resource Owner Password Credentials grant.

        Returns token dict on success, None if ROPC is not enabled.
        """
        payload = {
            "grant_type": "password",
            "client_id": AUTH0_CLIENT_ID,
            "username": email,
            "password": password,
            "audience": AUTH0_AUDIENCE,
            "scope": AUTH0_SCOPES,
        }
        headers = {
            "Content-Type": "application/json",
            "Auth0-Client": _AUTH0_CLIENT_INFO,
        }
        try:
            async with self._session.post(
                AUTH0_TOKEN_URL, json=payload, headers=headers
            ) as resp:
                _LOGGER.warning("AusPost ROPC: HTTP %s", resp.status)
                if resp.status == 403:
                    # ROPC not enabled for this client
                    return None
                if resp.status == 401:
                    raise InvalidCredentialsError("Invalid email or password")
                if resp.status == 429:
                    raise RateLimitError("Auth0 rate limit exceeded")
                if resp.status == 200:
                    data = await resp.json()
                    data["expires_at"] = time.time() + data.get("expires_in", 1800)
                    return data
                # Other errors mean ROPC is not available
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost ROPC: unexpected HTTP %s: %s",
                    resp.status,
                    body[:500],
                )
                return None
        except (InvalidCredentialsError, RateLimitError):
            raise
        except aiohttp.ClientError as err:
            _LOGGER.warning("AusPost ROPC: connection error: %s", err)
            return None

    async def _try_password_realm(
        self, email: str, password: str
    ) -> dict[str, Any] | None:
        """Attempt Auth0 password-realm grant type.

        This is an extended ROPC variant that specifies the database
        connection (realm). It may be enabled even when standard ROPC
        is not.

        Returns token dict on success, None if not available.
        """
        payload = {
            "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
            "client_id": AUTH0_CLIENT_ID,
            "username": email,
            "password": password,
            "audience": AUTH0_AUDIENCE,
            "scope": AUTH0_SCOPES,
            "realm": AUTH0_CONNECTION,
        }
        headers = {
            "Content-Type": "application/json",
            "Auth0-Client": _AUTH0_CLIENT_INFO,
        }
        try:
            async with self._session.post(
                AUTH0_TOKEN_URL, json=payload, headers=headers
            ) as resp:
                _LOGGER.warning("AusPost password-realm: HTTP %s", resp.status)
                if resp.status == 200:
                    data = await resp.json()
                    data["expires_at"] = time.time() + data.get(
                        "expires_in", 1800
                    )
                    return data
                if resp.status == 401:
                    body = await resp.text()
                    if "invalid_grant" in body or "Wrong" in body:
                        raise InvalidCredentialsError(
                            "Invalid email or password"
                        )
                    raise InvalidCredentialsError("Invalid email or password")
                if resp.status == 429:
                    raise RateLimitError(
                        "Too many login attempts. Please wait and try again."
                    )
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost password-realm: HTTP %s: %s",
                    resp.status,
                    body[:500],
                )
                return None
        except (InvalidCredentialsError, RateLimitError):
            raise
        except aiohttp.ClientError as err:
            _LOGGER.warning(
                "AusPost password-realm: connection error: %s", err
            )
            return None

    async def _try_co_authenticate(
        self, email: str, password: str
    ) -> dict[str, Any] | None:
        """Attempt Auth0 Cross-Origin Authentication.

        Uses the /co/authenticate API endpoint to obtain a login_ticket,
        then exchanges it via /authorize for an authorization code, then
        exchanges the code for tokens using PKCE.

        This completely bypasses Cloudflare bot protection because
        /co/authenticate is a JSON API endpoint (not a rendered login
        page) designed for SPA cross-origin authentication.

        Returns token dict on success, None if not available.
        """
        co_url = f"https://{AUTH0_DOMAIN}/co/authenticate"

        jar = aiohttp.CookieJar(unsafe=True)
        co_session = aiohttp.ClientSession(cookie_jar=jar)

        try:
            # ----------------------------------------------------------
            # Step 1: POST /co/authenticate to get a login_ticket
            # ----------------------------------------------------------
            async with co_session.post(
                co_url,
                json={
                    "client_id": AUTH0_CLIENT_ID,
                    "credential_type": (
                        "http://auth0.com/oauth/grant-type/password-realm"
                    ),
                    "username": email,
                    "password": password,
                    "realm": AUTH0_CONNECTION,
                },
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://auspost.com.au",
                    "Auth0-Client": _AUTH0_CLIENT_INFO,
                },
            ) as resp:
                _LOGGER.warning(
                    "AusPost /co/authenticate: HTTP %s", resp.status
                )

                if resp.status == 401:
                    body = await resp.text()
                    if (
                        "invalid_user_password" in body
                        or "Wrong" in body
                        or "invalid" in body.lower()
                    ):
                        raise InvalidCredentialsError(
                            "Invalid email or password"
                        )
                    raise InvalidCredentialsError("Invalid email or password")

                if resp.status == 403:
                    body = await resp.text()
                    _LOGGER.warning(
                        "AusPost /co/authenticate: 403 (may not be enabled): "
                        "%s",
                        body[:500],
                    )
                    return None

                if resp.status == 429:
                    raise RateLimitError(
                        "Too many login attempts. Please wait and try again."
                    )

                if resp.status != 200:
                    body = await resp.text()
                    _LOGGER.warning(
                        "AusPost /co/authenticate: HTTP %s: %s",
                        resp.status,
                        body[:500],
                    )
                    return None

                co_data = await resp.json()

            login_ticket = co_data.get("login_ticket")
            if not login_ticket:
                _LOGGER.warning(
                    "AusPost /co/authenticate: no login_ticket in response"
                )
                return None

            _LOGGER.warning(
                "AusPost /co/authenticate: got login_ticket=%s",
                _mask_token(login_ticket),
            )

            # ----------------------------------------------------------
            # Step 2: Generate PKCE parameters
            # ----------------------------------------------------------
            code_verifier, code_challenge = self._generate_pkce()

            nonce = (
                base64.urlsafe_b64encode(secrets.token_bytes(32))
                .rstrip(b"=")
                .decode("ascii")
            )

            # ----------------------------------------------------------
            # Step 3: GET /authorize with login_ticket and PKCE
            # Auth0 validates the login_ticket + co_verifier cookie and
            # redirects to redirect_uri?code=...
            # ----------------------------------------------------------
            params = urllib.parse.urlencode(
                {
                    "client_id": AUTH0_CLIENT_ID,
                    "response_type": "code",
                    "redirect_uri": AUTH0_REDIRECT_URI,
                    "scope": AUTH0_SCOPES,
                    "audience": AUTH0_AUDIENCE,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "nonce": nonce,
                    "auth0Client": _AUTH0_CLIENT_INFO,
                    "realm": AUTH0_CONNECTION,
                    "login_ticket": login_ticket,
                }
            )
            url = f"{AUTH0_AUTHORIZE_URL}?{params}"

            auth_code = None
            for hop in range(10):
                async with co_session.get(
                    url,
                    allow_redirects=False,
                    headers=_NAV_HEADERS,
                ) as resp:
                    _LOGGER.warning(
                        "AusPost /authorize (login_ticket) hop %d: HTTP %s",
                        hop,
                        resp.status,
                    )

                    if resp.status in (301, 302, 303):
                        location = resp.headers.get("Location", "")
                        _LOGGER.warning(
                            "AusPost /authorize hop %d: Location: %s",
                            hop,
                            location[:200] if location else "<empty>",
                        )
                        auth_code = self._extract_code_from_redirect(
                            location
                        )
                        if auth_code:
                            break
                        if not location:
                            break
                        # Resolve relative URLs
                        if location.startswith("/"):
                            location = (
                                f"https://{AUTH0_DOMAIN}{location}"
                            )
                        url = location
                        continue

                    if resp.status == 200:
                        body = await resp.text()
                        auth_code = self._extract_code_from_html(body)
                        if auth_code:
                            break
                        resume_url = self._extract_resume_url(body)
                        if resume_url:
                            url = resume_url
                            continue
                        _LOGGER.warning(
                            "AusPost /authorize: got 200 (no code found), "
                            "preview: %s",
                            body[:500],
                        )
                    break

            if not auth_code:
                _LOGGER.warning(
                    "AusPost /co/authenticate: could not obtain auth code "
                    "from /authorize redirect chain"
                )
                return None

            _LOGGER.warning(
                "AusPost /co/authenticate: auth_code=%s",
                _mask_token(auth_code),
            )

            # ----------------------------------------------------------
            # Step 4: Exchange authorization code for tokens
            # ----------------------------------------------------------
            async with co_session.post(
                AUTH0_TOKEN_URL,
                json={
                    "grant_type": "authorization_code",
                    "client_id": AUTH0_CLIENT_ID,
                    "code_verifier": code_verifier,
                    "code": auth_code,
                    "redirect_uri": AUTH0_REDIRECT_URI,
                },
                headers={
                    "Content-Type": "application/json",
                    "Auth0-Client": _AUTH0_CLIENT_INFO,
                },
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    _LOGGER.warning(
                        "AusPost /co/authenticate token exchange: "
                        "HTTP %s: %s",
                        resp.status,
                        body[:200],
                    )
                    return None
                data = await resp.json()

            data["expires_at"] = time.time() + data.get("expires_in", 1800)
            _LOGGER.warning(
                "AusPost /co/authenticate: login complete, "
                "access_token=%s",
                _mask_token(data.get("access_token")),
            )
            return data

        except (InvalidCredentialsError, RateLimitError):
            raise
        except aiohttp.ClientError as err:
            _LOGGER.warning(
                "AusPost /co/authenticate: connection error: %s", err
            )
            return None
        except Exception as err:
            _LOGGER.warning(
                "AusPost /co/authenticate: unexpected error: %s: %s",
                type(err).__name__,
                err,
            )
            return None
        finally:
            await co_session.close()

    async def _browser_simulation_login(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Perform the full Auth0 New Universal Login flow.

        Tries aiohttp with comprehensive browser headers first. If Cloudflare
        bot protection is detected, falls back to curl_cffi which impersonates
        Chrome's exact TLS fingerprint to bypass bot detection.
        """
        # Try aiohttp first (async, fast)
        try:
            return await self._browser_login_aiohttp(email, password)
        except CloudflareBlockedError:
            _LOGGER.warning(
                "AusPost: Cloudflare blocked aiohttp, "
                "falling back to curl_cffi (Chrome TLS impersonation)"
            )

        # Fall back to curl_cffi with Chrome TLS impersonation
        return await self._browser_login_curl_cffi(email, password)

    async def _browser_login_aiohttp(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Perform browser login using aiohttp with comprehensive headers.

        Raises CloudflareBlockedError if Cloudflare bot protection is detected.
        """
        jar = aiohttp.CookieJar(unsafe=True)
        auth_session = aiohttp.ClientSession(
            cookie_jar=jar,
            headers=_BROWSER_HEADERS,
        )

        try:
            # Step 1: Generate PKCE parameters
            code_verifier, code_challenge = self._generate_pkce()
            _LOGGER.warning("AusPost browser flow: step 1 PKCE generated")

            # Step 2: Initiate authorize flow
            state = await self._initiate_authorize(auth_session, code_challenge)
            _LOGGER.warning(
                "AusPost browser flow: step 2 authorize done, state=%s",
                state[:20] if state else "<none>",
            )

            # Step 3: Post credentials
            auth_code = await self._post_credentials(
                auth_session, email, password, state
            )
            _LOGGER.warning(
                "AusPost browser flow: step 3 got auth code=%s",
                _mask_token(auth_code),
            )

            # Step 4: Exchange code for tokens
            tokens = await self._exchange_code_for_tokens(
                auth_session, auth_code, code_verifier
            )
            _LOGGER.warning(
                "AusPost browser flow: step 4 token exchange OK, access_token=%s",
                _mask_token(tokens.get("access_token")),
            )

            self._update_tokens(tokens)
            return tokens

        except CloudflareBlockedError:
            raise
        except Exception as err:
            _LOGGER.warning(
                "AusPost browser flow FAILED: %s: %s",
                type(err).__name__,
                err,
            )
            raise
        finally:
            await auth_session.close()

    # ------------------------------------------------------------------
    # curl_cffi fallback (Chrome TLS impersonation)
    # ------------------------------------------------------------------

    async def _browser_login_curl_cffi(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Perform browser login via curl_cffi with Chrome TLS impersonation.

        curl_cffi impersonates Chrome's exact TLS fingerprint (JA3/JA4) at
        the libcurl level, which prevents Cloudflare from flagging the
        request as non-browser traffic. This is the key difference from
        aiohttp/cloudscraper which use Python's ssl module and have a
        detectable non-browser TLS fingerprint.

        curl_cffi is synchronous so we run it in an executor thread.
        """
        try:
            from curl_cffi import requests as cffi_requests  # noqa: F401
        except ImportError:
            raise AuthenticationError(
                "Cloudflare bot protection detected but 'curl_cffi' is not "
                "installed. Restart Home Assistant so the dependency is "
                "installed automatically, or run: pip install curl_cffi"
            )

        loop = asyncio.get_running_loop()
        tokens = await loop.run_in_executor(
            None,
            functools.partial(self._sync_browser_login, email, password),
        )
        self._update_tokens(tokens)
        return tokens

    def _sync_browser_login(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Full Auth0 login flow using curl_cffi (synchronous).

        Uses Chrome TLS impersonation to bypass Cloudflare fingerprinting.
        """
        from curl_cffi.requests import Session

        session = Session(impersonate="chrome124")
        session.headers.update(_BROWSER_HEADERS)

        _LOGGER.warning("AusPost curl_cffi: starting login flow (chrome124 TLS)")

        # Step 1: PKCE
        code_verifier, code_challenge = self._generate_pkce()

        # Step 2: GET /authorize
        nonce = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        params = {
            "client_id": AUTH0_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": AUTH0_REDIRECT_URI,
            "scope": AUTH0_SCOPES,
            "audience": AUTH0_AUDIENCE,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "auth0Client": _AUTH0_CLIENT_INFO,
        }

        resp = session.get(
            AUTH0_AUTHORIZE_URL, params=params, headers=_NAV_HEADERS
        )
        _LOGGER.warning(
            "AusPost curl_cffi authorize: HTTP %s, URL: %s",
            resp.status_code,
            str(resp.url)[:120],
        )

        if resp.status_code != 200:
            body = resp.text[:500]
            _LOGGER.warning(
                "AusPost curl_cffi authorize: non-200 body: %s", body
            )
            if self._is_cloudflare_challenge(resp.status_code, resp.text):
                raise CloudflareBlockedError(
                    "Cloudflare blocked the request even with Chrome TLS "
                    "impersonation. Australia Post may require browser-level "
                    "JavaScript execution."
                )
            raise AuthenticationError(
                f"authorize failed via curl_cffi (HTTP {resp.status_code})"
            )

        state = self._extract_state(str(resp.url), resp.text)
        if not state:
            _LOGGER.warning(
                "AusPost curl_cffi: could not find state. URL: %s, "
                "HTML preview: %s",
                str(resp.url)[:200],
                resp.text[:500],
            )
            raise AuthenticationError(
                "Could not extract state from Auth0 login page (curl_cffi)"
            )

        _LOGGER.warning(
            "AusPost curl_cffi: authorize OK, state=%s",
            state[:20],
        )

        # Step 3: POST credentials to /u/login
        login_url = f"{AUTH0_LOGIN_URL}?state={urllib.parse.quote(state)}"
        payload = urllib.parse.urlencode(
            {
                "state": state,
                "username": email,
                "password": password,
                "action": "default",
            }
        )

        post_headers = {
            **_FORM_POST_HEADERS,
            "Origin": f"https://{AUTH0_DOMAIN}",
            "Referer": login_url,
        }

        resp = session.post(
            login_url,
            data=payload,
            headers=post_headers,
            allow_redirects=False,
        )
        _LOGGER.warning(
            "AusPost curl_cffi POST /u/login: HTTP %s", resp.status_code
        )

        auth_code = self._handle_login_response_sync(session, resp)

        if not auth_code:
            # Try Classic Universal Login as fallback
            auth_code = self._sync_classic_login(
                session, email, password, state
            )

        if not auth_code:
            raise AuthenticationError(
                "Could not obtain authorization code via curl_cffi"
            )

        _LOGGER.warning(
            "AusPost curl_cffi: got auth code=%s", _mask_token(auth_code)
        )

        # Step 4: Exchange code for tokens
        token_payload = {
            "grant_type": "authorization_code",
            "client_id": AUTH0_CLIENT_ID,
            "code_verifier": code_verifier,
            "code": auth_code,
            "redirect_uri": AUTH0_REDIRECT_URI,
        }

        resp = session.post(
            AUTH0_TOKEN_URL,
            json=token_payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
            },
        )

        if resp.status_code != 200:
            _LOGGER.error(
                "AusPost curl_cffi token exchange: HTTP %s: %s",
                resp.status_code,
                resp.text[:200],
            )
            raise AuthenticationError(
                f"Token exchange failed via curl_cffi (HTTP {resp.status_code})"
            )

        data = resp.json()
        data["expires_at"] = time.time() + data.get("expires_in", 1800)
        _LOGGER.warning(
            "AusPost curl_cffi: login complete, access_token=%s",
            _mask_token(data.get("access_token")),
        )
        return data

    def _handle_login_response_sync(
        self, session: Any, resp: Any
    ) -> str | None:
        """Process the /u/login response synchronously."""
        if resp.status_code in (401, 403):
            body = resp.text
            if "Wrong email or password" in body or "invalid" in body.lower():
                raise InvalidCredentialsError("Invalid email or password")
            raise InvalidCredentialsError("Invalid email or password")

        if resp.status_code == 429:
            raise RateLimitError(
                "Too many login attempts. Please wait and try again."
            )

        if resp.status_code in (301, 302, 303):
            location = resp.headers.get("Location", "")
            _LOGGER.warning(
                "AusPost curl_cffi /u/login: redirect to: %s",
                location[:200] if location else "<empty>",
            )
            code = self._extract_code_from_redirect(location)
            if code:
                return code
            if location:
                return self._sync_follow_redirects(session, location)

        if resp.status_code == 200:
            body = resp.text
            if (
                "Wrong email or password" in body
                or "wrong-credentials" in body
            ):
                raise InvalidCredentialsError("Invalid email or password")
            code = self._extract_code_from_html(body)
            if code:
                return code
            resume_url = self._extract_resume_url(body)
            if resume_url:
                return self._sync_follow_redirects(session, resume_url)

        return None

    def _sync_classic_login(
        self,
        session: Any,
        email: str,
        password: str,
        state: str,
    ) -> str | None:
        """Attempt Classic Universal Login via curl_cffi."""
        login_url = f"https://{AUTH0_DOMAIN}/usernamepassword/login"
        payload = {
            "client_id": AUTH0_CLIENT_ID,
            "redirect_uri": AUTH0_REDIRECT_URI,
            "tenant": "prod.auspost",
            "response_type": "code",
            "scope": AUTH0_SCOPES,
            "audience": AUTH0_AUDIENCE,
            "connection": AUTH0_CONNECTION,
            "username": email,
            "password": password,
            "state": state,
        }

        _LOGGER.warning(
            "AusPost curl_cffi: classic login POST /usernamepassword/login"
        )
        resp = session.post(
            login_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
                "Origin": f"https://{AUTH0_DOMAIN}",
            },
        )
        _LOGGER.warning(
            "AusPost curl_cffi classic login: HTTP %s", resp.status_code
        )

        if resp.status_code == 401:
            raise InvalidCredentialsError("Invalid email or password")
        if resp.status_code == 429:
            raise RateLimitError(
                "Too many login attempts. Please wait and try again."
            )
        if resp.status_code != 200:
            return None

        html = resp.text
        try:
            wa, wresult, wctx = self._parse_callback_form(html)
        except AuthenticationError:
            return None

        callback_url = f"https://{AUTH0_DOMAIN}/login/callback"
        resp = session.post(
            callback_url,
            data={"wa": wa, "wresult": wresult, "wctx": wctx},
            allow_redirects=False,
        )
        if resp.status_code not in (301, 302, 303):
            return None

        location = resp.headers.get("Location", "")
        code = self._extract_code_from_redirect(location)
        if code:
            return code
        if location:
            return self._sync_follow_redirects(session, location)
        return None

    def _sync_follow_redirects(
        self, session: Any, url: str, max_hops: int = 10
    ) -> str:
        """Follow redirect chain using the sync session (curl_cffi)."""
        for hop in range(max_hops):
            _LOGGER.warning(
                "AusPost curl_cffi redirect hop %d: GET %s",
                hop + 1,
                url[:200],
            )
            resp = session.get(url, allow_redirects=False)
            _LOGGER.warning(
                "AusPost curl_cffi redirect hop %d: HTTP %s",
                hop + 1,
                resp.status_code,
            )

            if resp.status_code in (301, 302, 303):
                location = resp.headers.get("Location", "")
                code = self._extract_code_from_redirect(location)
                if code:
                    return code
                if not location:
                    break
                if location.startswith("/"):
                    location = f"https://{AUTH0_DOMAIN}{location}"
                url = location
                continue

            if resp.status_code == 200:
                code = self._extract_code_from_html(resp.text)
                if code:
                    return code
                resume_url = self._extract_resume_url(resp.text)
                if resume_url:
                    url = resume_url
                    continue
            break

        raise AuthenticationError(
            "Could not extract auth code from redirect chain"
        )

    # ------------------------------------------------------------------
    # Cloudflare detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_cloudflare_challenge(status_code: int, body: str) -> bool:
        """Detect whether an HTTP response is a Cloudflare challenge page."""
        if status_code not in (403, 503):
            return False
        body_lower = body.lower()
        return any(marker.lower() in body_lower for marker in _CF_MARKERS)

    @staticmethod
    def _generate_pkce() -> tuple[str, str]:
        """Generate PKCE code_verifier and code_challenge (S256)."""
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )
        return code_verifier, code_challenge

    async def _initiate_authorize(
        self, session: aiohttp.ClientSession, code_challenge: str
    ) -> str:
        """GET /authorize to start the OAuth2 flow.

        Follows redirects to the /u/login page and extracts the state parameter.

        Returns:
            The state value from the login page.
        """
        nonce = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )

        params = {
            "client_id": AUTH0_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": AUTH0_REDIRECT_URI,
            "scope": AUTH0_SCOPES,
            "audience": AUTH0_AUDIENCE,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "auth0Client": _AUTH0_CLIENT_INFO,
        }

        async with session.get(
            AUTH0_AUTHORIZE_URL,
            params=params,
            allow_redirects=True,
            headers=_NAV_HEADERS,
        ) as resp:
            _LOGGER.warning(
                "AusPost authorize: HTTP %s, final URL: %s",
                resp.status,
                str(resp.url)[:120],
            )
            if resp.status != 200:
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost authorize: non-200 body: %s", body[:500]
                )
                if self._is_cloudflare_challenge(resp.status, body):
                    raise CloudflareBlockedError(
                        "Cloudflare bot protection blocked the authorize "
                        f"request (HTTP {resp.status})"
                    )
                raise AuthenticationError(
                    f"Failed to initiate auth flow (HTTP {resp.status})"
                )
            html = await resp.text()
            final_url = str(resp.url)

        _LOGGER.warning(
            "AusPost authorize: page title: %s, body length: %d",
            (re.search(r"<title>(.*?)</title>", html, re.IGNORECASE) or [None, "unknown"])[1],
            len(html),
        )

        # Extract state from the URL query params or the HTML page
        state = self._extract_state(final_url, html)
        if not state:
            _LOGGER.warning(
                "AusPost authorize: could not find state in URL or HTML. "
                "URL: %s, HTML preview: %s",
                final_url[:200],
                html[:500],
            )
            raise AuthenticationError(
                "Could not extract state from Auth0 login page"
            )
        return state

    @staticmethod
    def _extract_state(url: str, html: str) -> str | None:
        """Extract the state parameter from the login page URL or HTML.

        Auth0 New Universal Login includes state in the URL query string
        of /u/login?state=... and also embeds it in the page HTML.
        """
        # Try URL query params first
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if "state" in params:
            return params["state"][0]

        # Try hidden input field
        match = re.search(r'name="state"\s+value="([^"]+)"', html)
        if match:
            return match.group(1)

        # Try JSON config block
        match = re.search(r'"state"\s*:\s*"([^"]+)"', html)
        if match:
            return match.group(1)

        return None

    async def _post_credentials(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        state: str,
    ) -> str:
        """Submit credentials to Auth0 and extract the authorization code.

        For Auth0 New Universal Login, credentials are POSTed to /u/login.
        On success, Auth0 responds with a redirect containing the auth code.

        Returns:
            The authorization code.
        """
        # Try New Universal Login endpoint first (/u/login)
        code = await self._try_new_universal_login(
            session, email, password, state
        )
        if code:
            return code

        # Fall back to Classic Universal Login (/usernamepassword/login)
        return await self._try_classic_login(session, email, password, state)

    async def _try_new_universal_login(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        state: str,
    ) -> str | None:
        """Attempt Auth0 New Universal Login flow.

        POSTs to /u/login with form data. Auth0 responds with a 302
        redirect chain: first to /authorize/resume?state=..., then
        to redirect_uri?code=... We must follow the chain to extract
        the authorization code.
        """
        login_url = f"{AUTH0_LOGIN_URL}?state={urllib.parse.quote(state)}"

        payload = urllib.parse.urlencode({
            "state": state,
            "username": email,
            "password": password,
            "action": "default",
        })

        try:
            async with session.post(
                login_url,
                data=payload,
                allow_redirects=False,
                headers={
                    **_FORM_POST_HEADERS,
                    "Origin": f"https://{AUTH0_DOMAIN}",
                    "Referer": login_url,
                },
            ) as resp:
                _LOGGER.warning(
                    "AusPost POST /u/login: HTTP %s", resp.status
                )

                if resp.status in (401, 403):
                    body = await resp.text()
                    _LOGGER.warning(
                        "AusPost POST /u/login: 401/403 body: %s",
                        body[:500],
                    )
                    if "Wrong email or password" in body or "invalid" in body.lower():
                        raise InvalidCredentialsError(
                            "Invalid email or password"
                        )
                    raise InvalidCredentialsError("Invalid email or password")

                if resp.status == 429:
                    raise RateLimitError(
                        "Too many login attempts. Please wait and try again."
                    )

                # On success, Auth0 responds with 302. The first hop is
                # typically to /authorize/resume (NOT directly to
                # redirect_uri with the code). We must follow the chain.
                if resp.status in (301, 302, 303):
                    location = resp.headers.get("Location", "")
                    _LOGGER.warning(
                        "AusPost POST /u/login: redirect to: %s",
                        location[:200] if location else "<empty>",
                    )
                    code = self._extract_code_from_redirect(location)
                    if code:
                        return code
                    # Follow the Auth0 internal redirect chain
                    if location:
                        return await self._follow_redirect_chain(
                            session, location
                        )

                # If 200, the login page re-rendered (error or needs action)
                if resp.status == 200:
                    body = await resp.text()
                    _LOGGER.warning(
                        "AusPost POST /u/login: got 200 (page re-rendered), "
                        "body length=%d, preview: %s",
                        len(body),
                        body[:500],
                    )
                    if (
                        "Wrong email or password" in body
                        or "wrong-credentials" in body
                    ):
                        raise InvalidCredentialsError(
                            "Invalid email or password"
                        )
                    code = self._extract_code_from_html(body)
                    if code:
                        return code
                    resume_url = self._extract_resume_url(body)
                    if resume_url:
                        _LOGGER.warning(
                            "AusPost POST /u/login: found resume URL: %s",
                            resume_url[:200],
                        )
                        return await self._follow_redirect_chain(
                            session, resume_url
                        )

                body = await resp.text()
                _LOGGER.warning(
                    "AusPost POST /u/login: unexpected status %s, body: %s",
                    resp.status,
                    body[:500],
                )

        except (InvalidCredentialsError, RateLimitError):
            raise
        except aiohttp.ClientError as err:
            _LOGGER.warning(
                "AusPost POST /u/login: connection error: %s", err
            )
            return None

        return None

    async def _try_classic_login(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        state: str,
    ) -> str:
        """Attempt Auth0 Classic Universal Login flow.

        Uses /usernamepassword/login to submit credentials, then follows
        the WS-Fed callback to get the authorization code.
        """
        login_url = f"https://{AUTH0_DOMAIN}/usernamepassword/login"

        payload = {
            "client_id": AUTH0_CLIENT_ID,
            "redirect_uri": AUTH0_REDIRECT_URI,
            "tenant": "prod.auspost",
            "response_type": "code",
            "scope": AUTH0_SCOPES,
            "audience": AUTH0_AUDIENCE,
            "connection": AUTH0_CONNECTION,
            "username": email,
            "password": password,
            "state": state,
        }

        _LOGGER.warning("AusPost classic login: POST /usernamepassword/login")
        async with session.post(
            login_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
                "Origin": f"https://{AUTH0_DOMAIN}",
            },
        ) as resp:
            _LOGGER.warning(
                "AusPost classic login: HTTP %s", resp.status
            )
            if resp.status == 401:
                raise InvalidCredentialsError("Invalid email or password")
            if resp.status == 429:
                raise RateLimitError(
                    "Too many login attempts. Please wait and try again."
                )
            if resp.status != 200:
                body = await resp.text()
                _LOGGER.warning(
                    "AusPost classic login: failed HTTP %s: %s",
                    resp.status,
                    body[:500],
                )
                raise AuthenticationError(
                    f"Classic login failed (HTTP {resp.status})"
                )
            html = await resp.text()

        _LOGGER.warning(
            "AusPost classic login: got response, length=%d", len(html)
        )
        # Parse the WS-Fed callback form
        wa, wresult, wctx = self._parse_callback_form(html)

        # POST the callback form
        callback_url = f"https://{AUTH0_DOMAIN}/login/callback"
        form_data = aiohttp.FormData()
        form_data.add_field("wa", wa)
        form_data.add_field("wresult", wresult)
        form_data.add_field("wctx", wctx)

        async with session.post(
            callback_url,
            data=form_data,
            allow_redirects=False,
        ) as resp:
            if resp.status not in (301, 302, 303):
                raise AuthenticationError(
                    f"Expected redirect from /login/callback, got {resp.status}"
                )
            location = resp.headers.get("Location", "")

        code = self._extract_code_from_redirect(location)
        if not code:
            raise AuthenticationError(
                "No authorization code in callback redirect"
            )
        return code

    async def _follow_redirect_chain(
        self, session: aiohttp.ClientSession, url: str, max_hops: int = 10
    ) -> str:
        """Follow a redirect chain until we find the authorization code.

        After POST /u/login returns 302, Auth0 typically redirects to
        /authorize/resume?state=... which then redirects to the
        redirect_uri?code=...&state=... We follow each hop (without
        leaving the Auth0 domain for the actual redirect_uri) and
        extract the code from the final Location header.
        """
        for hop in range(max_hops):
            _LOGGER.warning(
                "AusPost redirect chain hop %d: GET %s",
                hop + 1,
                url[:200],
            )
            async with session.get(url, allow_redirects=False) as resp:
                _LOGGER.warning(
                    "AusPost redirect chain hop %d: HTTP %s",
                    hop + 1,
                    resp.status,
                )
                if resp.status in (301, 302, 303):
                    location = resp.headers.get("Location", "")
                    _LOGGER.warning(
                        "AusPost redirect chain hop %d: Location: %s",
                        hop + 1,
                        location[:200] if location else "<empty>",
                    )
                    code = self._extract_code_from_redirect(location)
                    if code:
                        _LOGGER.warning(
                            "AusPost redirect chain: found auth code at hop %d",
                            hop + 1,
                        )
                        return code
                    if not location:
                        break
                    # Resolve relative URLs
                    if location.startswith("/"):
                        location = f"https://{AUTH0_DOMAIN}{location}"
                    url = location
                    continue

                # Non-redirect response -- check for code in body
                if resp.status == 200:
                    body = await resp.text()
                    code = self._extract_code_from_html(body)
                    if code:
                        return code
                    resume_url = self._extract_resume_url(body)
                    if resume_url:
                        url = resume_url
                        continue
                break

        raise AuthenticationError(
            "Could not extract authorization code from Auth0 redirect chain"
        )

    async def _exchange_code_for_tokens(
        self,
        session: aiohttp.ClientSession,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
        payload = {
            "grant_type": "authorization_code",
            "client_id": AUTH0_CLIENT_ID,
            "code_verifier": code_verifier,
            "code": code,
            "redirect_uri": AUTH0_REDIRECT_URI,
        }

        async with session.post(
            AUTH0_TOKEN_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
            },
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.error(
                    "Token exchange failed (HTTP %s): %s",
                    resp.status,
                    text[:200],
                )
                raise AuthenticationError(
                    f"Token exchange failed (HTTP {resp.status})"
                )
            data = await resp.json()

        data["expires_at"] = time.time() + data.get("expires_in", 1800)
        return data

    async def async_refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """Use a refresh token to obtain new tokens.

        Args:
            refresh_token: The refresh token.

        Returns:
            Dict with new token data.

        Raises:
            TokenExpiredError: If the refresh token is invalid/expired.
        """
        payload = {
            "grant_type": "refresh_token",
            "client_id": AUTH0_CLIENT_ID,
            "refresh_token": refresh_token,
        }

        async with self._session.post(
            AUTH0_TOKEN_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Auth0-Client": _AUTH0_CLIENT_INFO,
            },
        ) as resp:
            if resp.status in (401, 403):
                raise TokenExpiredError(
                    "Refresh token is invalid or expired"
                )
            if resp.status == 429:
                raise RateLimitError("Auth0 rate limit exceeded during refresh")
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.error(
                    "Token refresh failed (HTTP %s): %s",
                    resp.status,
                    text[:200],
                )
                raise AuthenticationError(
                    f"Token refresh failed (HTTP {resp.status})"
                )
            data = await resp.json()

        data["expires_at"] = time.time() + data.get("expires_in", 1800)
        # Preserve the refresh_token if the response doesn't include a new one
        if "refresh_token" not in data:
            data["refresh_token"] = refresh_token
        return data

    def _update_tokens(self, tokens: dict[str, Any]) -> None:
        """Update internal token state from a token response dict."""
        self._access_token = tokens.get("access_token")
        self._refresh_token = tokens.get("refresh_token", self._refresh_token)
        self._id_token = tokens.get("id_token", self._id_token)
        self._expires_at = tokens.get("expires_at", 0.0)

    @staticmethod
    def _extract_code_from_redirect(location: str) -> str | None:
        """Extract the authorization code from a redirect Location header."""
        if not location:
            return None
        parsed = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed.query)
        codes = params.get("code")
        return codes[0] if codes else None

    @staticmethod
    def _extract_code_from_html(html: str) -> str | None:
        """Extract an authorization code embedded in HTML (e.g. in a script)."""
        match = re.search(r'["\']code["\']\s*:\s*["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _extract_resume_url(html: str) -> str | None:
        """Extract a resume/continue URL from Auth0 HTML response."""
        match = re.search(
            r'action="(https://[^"]*(?:/authorize/resume|/continue)[^"]*)"',
            html,
        )
        if match:
            return html_unescape(match.group(1))

        match = re.search(
            r'(?:resume|continue).*?["\'](https://[^"\']+)["\']', html
        )
        if match:
            return html_unescape(match.group(1))
        return None

    @staticmethod
    def _parse_callback_form(html: str) -> tuple[str, str, str]:
        """Parse the WS-Fed callback form from Classic Universal Login.

        Extracts wa, wresult, and wctx hidden form fields.
        """
        fields: dict[str, str] = {}
        for name in ("wa", "wresult", "wctx"):
            match = re.search(
                rf'name="{name}"\s+value="([^"]*)"', html, re.DOTALL
            )
            if not match:
                raise AuthenticationError(
                    f"Missing '{name}' in Auth0 callback form"
                )
            fields[name] = html_unescape(match.group(1))
        return fields["wa"], fields["wresult"], fields["wctx"]
