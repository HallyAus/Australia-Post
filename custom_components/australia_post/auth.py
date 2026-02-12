"""Auth0 authentication handler for Australia Post MyPost Business."""

from __future__ import annotations

import base64
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
        self._on_token_refresh: (
            Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | None
        ) = None

    def set_token_refresh_callback(
        self,
        callback: Callable[[dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Set a callback to be called when tokens are refreshed."""
        self._on_token_refresh = callback

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

        Raises:
            TokenExpiredError: If no valid token and no refresh token available.
        """
        if self._access_token and time.time() < self._expires_at - 60:
            return self._access_token

        if self._refresh_token:
            _LOGGER.debug("Access token expired, refreshing")
            tokens = await self.async_refresh_token(self._refresh_token)
            self._update_tokens(tokens)
            if self._on_token_refresh:
                await self._on_token_refresh(tokens)
            return self._access_token  # type: ignore[return-value]

        raise TokenExpiredError("No valid token and no refresh token available")

    async def async_login(self, email: str, password: str) -> dict[str, Any]:
        """Perform complete Auth0 login and return token dict.

        Tries ROPC (Resource Owner Password Credentials) first as the simpler
        path. Falls back to browser-simulated New Universal Login flow if ROPC
        is not available.

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
        # Try ROPC first (simpler, but may not be enabled for SPA clients)
        ropc_result = await self._try_ropc_login(email, password)
        if ropc_result is not None:
            _LOGGER.warning("AusPost login: ROPC succeeded")
            self._update_tokens(ropc_result)
            return ropc_result

        _LOGGER.warning("AusPost login: ROPC not available, trying browser flow")
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

    async def _browser_simulation_login(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Perform the full Auth0 New Universal Login flow.

        Steps:
        1. Generate PKCE code_verifier and code_challenge
        2. GET /authorize to initiate the flow and get the login page
        3. POST credentials to /u/login
        4. Extract auth code from redirect
        5. Exchange code for tokens
        """
        # Create a dedicated session with cookie support for the login flow
        jar = aiohttp.CookieJar(unsafe=True)
        auth_session = aiohttp.ClientSession(
            cookie_jar=jar,
            headers={"User-Agent": _USER_AGENT},
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

        except Exception as err:
            _LOGGER.warning(
                "AusPost browser flow FAILED: %s: %s",
                type(err).__name__,
                err,
            )
            raise
        finally:
            await auth_session.close()

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
            AUTH0_AUTHORIZE_URL, params=params, allow_redirects=True
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
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"https://{AUTH0_DOMAIN}",
                    "Referer": login_url,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-AU,en;q=0.9",
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
