"""Config flow for Australia Post MyPost Business."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import AusPostApiClient
from .auth import AusPostAuth
from .const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_PASSWORD,
    CONF_ACCESS_TOKEN,
    CONF_ACCOUNT_NUMBER,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_EMAIL,
    CONF_EXPIRES_AT,
    CONF_ID_TOKEN,
    CONF_ORGANISATION_ID,
    CONF_ORGANISATION_NAME,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)
from .exceptions import (
    AuthenticationError,
    CloudflareBlockedError,
    InvalidCredentialsError,
    RateLimitError,
)
from .models import Organisation

_LOGGER = logging.getLogger(__name__)

API_KEY_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
        vol.Required(CONF_ACCOUNT_NUMBER): str,
    }
)

PASSWORD_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class AusPostConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow for Australia Post MyPost Business."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialise the config flow."""
        self._token_data: dict[str, Any] = {}
        self._email: str = ""
        self._organisations: list[Organisation] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step: choose authentication method."""
        if user_input is not None:
            method = user_input.get(CONF_AUTH_METHOD, AUTH_METHOD_API_KEY)
            if method == AUTH_METHOD_API_KEY:
                return await self.async_step_api_credentials()
            return await self.async_step_password()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_AUTH_METHOD, default=AUTH_METHOD_API_KEY
                    ): vol.In(
                        {
                            AUTH_METHOD_API_KEY: "API Credentials (Recommended)",
                            AUTH_METHOD_PASSWORD: "Email + Password",
                        }
                    ),
                }
            ),
        )

    # ------------------------------------------------------------------
    # API credentials flow (client_credentials - recommended)
    # ------------------------------------------------------------------

    async def async_step_api_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle API credentials entry (client_id + client_secret)."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                session = async_create_clientsession(self.hass)
                auth = AusPostAuth(session)
                tokens = await auth.async_login_client_credentials(
                    user_input[CONF_CLIENT_ID],
                    user_input[CONF_CLIENT_SECRET],
                )

                account_number = user_input[CONF_ACCOUNT_NUMBER]
                await self.async_set_unique_id(account_number)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"AusPost - {account_number}",
                    data={
                        CONF_AUTH_METHOD: AUTH_METHOD_API_KEY,
                        CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                        CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                        CONF_ACCOUNT_NUMBER: account_number,
                        CONF_ACCESS_TOKEN: tokens["access_token"],
                        CONF_REFRESH_TOKEN: "",
                        CONF_ID_TOKEN: "",
                        CONF_EXPIRES_AT: tokens["expires_at"],
                        CONF_ORGANISATION_ID: "",
                        CONF_ORGANISATION_NAME: "",
                    },
                )

            except InvalidCredentialsError as err:
                _LOGGER.warning(
                    "AusPost API credentials: invalid: %s", err
                )
                errors["base"] = "invalid_auth"
            except RateLimitError as err:
                _LOGGER.warning(
                    "AusPost API credentials: rate limited: %s", err
                )
                errors["base"] = "rate_limited"
            except AuthenticationError as err:
                _LOGGER.warning(
                    "AusPost API credentials: auth error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError as err:
                _LOGGER.warning(
                    "AusPost API credentials: connection error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception(
                    "Unexpected error during API credential validation"
                )
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="api_credentials",
            data_schema=API_KEY_SCHEMA,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Email + password flow (browser simulation - legacy)
    # ------------------------------------------------------------------

    async def async_step_password(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle email + password entry."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._email = user_input[CONF_EMAIL]
            try:
                session = async_create_clientsession(self.hass)
                auth = AusPostAuth(session)
                tokens = await auth.async_login(
                    user_input[CONF_EMAIL], user_input[CONF_PASSWORD]
                )

                # Fetch organisations to get account info
                api = AusPostApiClient(session=session, auth=auth)
                organisations = await api.async_get_organisations()

                if not organisations:
                    errors["base"] = "no_organisations"
                elif len(organisations) == 1:
                    org = organisations[0]
                    await self.async_set_unique_id(org.account_number)
                    self._abort_if_unique_id_configured()

                    return self.async_create_entry(
                        title=f"AusPost - {org.name}",
                        data={
                            CONF_AUTH_METHOD: AUTH_METHOD_PASSWORD,
                            CONF_EMAIL: user_input[CONF_EMAIL],
                            CONF_ACCESS_TOKEN: tokens["access_token"],
                            CONF_REFRESH_TOKEN: tokens.get(
                                "refresh_token", ""
                            ),
                            CONF_ID_TOKEN: tokens.get("id_token", ""),
                            CONF_EXPIRES_AT: tokens["expires_at"],
                            CONF_ACCOUNT_NUMBER: org.account_number,
                            CONF_ORGANISATION_ID: org.organisation_id,
                            CONF_ORGANISATION_NAME: org.name,
                        },
                    )
                else:
                    self._token_data = {
                        CONF_AUTH_METHOD: AUTH_METHOD_PASSWORD,
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_ACCESS_TOKEN: tokens["access_token"],
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token", ""),
                        CONF_ID_TOKEN: tokens.get("id_token", ""),
                        CONF_EXPIRES_AT: tokens["expires_at"],
                    }
                    self._organisations = organisations
                    return await self.async_step_select_organisation()

            except InvalidCredentialsError as err:
                _LOGGER.warning("AusPost login: invalid credentials: %s", err)
                errors["base"] = "invalid_auth"
            except RateLimitError as err:
                _LOGGER.warning("AusPost login: rate limited: %s", err)
                errors["base"] = "rate_limited"
            except CloudflareBlockedError as err:
                _LOGGER.warning(
                    "AusPost login: Cloudflare blocked: %s", err
                )
                errors["base"] = "cloudflare_blocked"
            except AuthenticationError as err:
                _LOGGER.warning(
                    "AusPost login: auth error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError as err:
                _LOGGER.warning(
                    "AusPost login: connection error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during authentication")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="password",
            data_schema=PASSWORD_SCHEMA,
            errors=errors,
        )

    async def async_step_select_organisation(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let user pick which organisation to track."""
        if user_input is not None:
            selected_id = user_input["organisation"]
            org = next(
                o
                for o in self._organisations
                if o.organisation_id == selected_id
            )

            await self.async_set_unique_id(org.account_number)
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=f"AusPost - {org.name}",
                data={
                    **self._token_data,
                    CONF_ACCOUNT_NUMBER: org.account_number,
                    CONF_ORGANISATION_ID: org.organisation_id,
                    CONF_ORGANISATION_NAME: org.name,
                },
            )

        org_options = {
            org.organisation_id: f"{org.name} ({org.account_number})"
            for org in self._organisations
        }

        return self.async_show_form(
            step_id="select_organisation",
            data_schema=vol.Schema(
                {vol.Required("organisation"): vol.In(org_options)}
            ),
        )

    # ------------------------------------------------------------------
    # Re-authentication
    # ------------------------------------------------------------------

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication when tokens expire."""
        entry = self._get_reauth_entry()
        auth_method = entry.data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)

        if auth_method == AUTH_METHOD_API_KEY:
            return await self.async_step_reauth_api_credentials()
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_api_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-authenticate with API credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                session = async_create_clientsession(self.hass)
                auth = AusPostAuth(session)
                tokens = await auth.async_login_client_credentials(
                    user_input[CONF_CLIENT_ID],
                    user_input[CONF_CLIENT_SECRET],
                )

                entry = self._get_reauth_entry()
                return self.async_update_reload_and_abort(
                    entry,
                    data={
                        **entry.data,
                        CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                        CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                        CONF_ACCESS_TOKEN: tokens["access_token"],
                        CONF_EXPIRES_AT: tokens["expires_at"],
                    },
                )
            except InvalidCredentialsError as err:
                _LOGGER.warning(
                    "AusPost reauth API: invalid credentials: %s", err
                )
                errors["base"] = "invalid_auth"
            except RateLimitError as err:
                _LOGGER.warning(
                    "AusPost reauth API: rate limited: %s", err
                )
                errors["base"] = "rate_limited"
            except AuthenticationError as err:
                _LOGGER.warning(
                    "AusPost reauth API: auth error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError as err:
                _LOGGER.warning(
                    "AusPost reauth API: connection error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception(
                    "Unexpected error during API re-authentication"
                )
                errors["base"] = "unknown"

        reauth_entry = self._get_reauth_entry()
        default_client_id = reauth_entry.data.get(CONF_CLIENT_ID, "")

        return self.async_show_form(
            step_id="reauth_api_credentials",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_CLIENT_ID, default=default_client_id
                    ): str,
                    vol.Required(CONF_CLIENT_SECRET): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-authenticate with email and password."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                session = async_create_clientsession(self.hass)
                auth = AusPostAuth(session)
                tokens = await auth.async_login(
                    user_input[CONF_EMAIL], user_input[CONF_PASSWORD]
                )

                entry = self._get_reauth_entry()
                return self.async_update_reload_and_abort(
                    entry,
                    data={
                        **entry.data,
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_ACCESS_TOKEN: tokens["access_token"],
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token", ""),
                        CONF_ID_TOKEN: tokens.get("id_token", ""),
                        CONF_EXPIRES_AT: tokens["expires_at"],
                    },
                )
            except InvalidCredentialsError as err:
                _LOGGER.warning("AusPost reauth: invalid credentials: %s", err)
                errors["base"] = "invalid_auth"
            except RateLimitError as err:
                _LOGGER.warning("AusPost reauth: rate limited: %s", err)
                errors["base"] = "rate_limited"
            except CloudflareBlockedError as err:
                _LOGGER.warning(
                    "AusPost reauth: Cloudflare blocked: %s", err
                )
                errors["base"] = "cloudflare_blocked"
            except AuthenticationError as err:
                _LOGGER.warning(
                    "AusPost reauth: auth error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError as err:
                _LOGGER.warning(
                    "AusPost reauth: connection error: %s: %s",
                    type(err).__name__,
                    err,
                )
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during re-authentication")
                errors["base"] = "unknown"

        reauth_entry = self._get_reauth_entry()
        default_email = reauth_entry.data.get(CONF_EMAIL, "")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=default_email): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )
