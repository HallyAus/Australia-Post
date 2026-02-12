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
    CONF_ACCESS_TOKEN,
    CONF_ACCOUNT_NUMBER,
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
    InvalidCredentialsError,
    RateLimitError,
)
from .models import Organisation

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema(
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
        """Handle the initial step: email + password entry."""
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
                    # Single organisation - create entry directly
                    org = organisations[0]
                    await self.async_set_unique_id(org.account_number)
                    self._abort_if_unique_id_configured()

                    return self.async_create_entry(
                        title=f"AusPost - {org.name}",
                        data={
                            CONF_EMAIL: user_input[CONF_EMAIL],
                            CONF_ACCESS_TOKEN: tokens["access_token"],
                            CONF_REFRESH_TOKEN: tokens.get("refresh_token", ""),
                            CONF_ID_TOKEN: tokens.get("id_token", ""),
                            CONF_EXPIRES_AT: tokens["expires_at"],
                            CONF_ACCOUNT_NUMBER: org.account_number,
                            CONF_ORGANISATION_ID: org.organisation_id,
                            CONF_ORGANISATION_NAME: org.name,
                        },
                    )
                else:
                    # Multiple organisations - let user pick
                    self._token_data = {
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_ACCESS_TOKEN: tokens["access_token"],
                        CONF_REFRESH_TOKEN: tokens.get("refresh_token", ""),
                        CONF_ID_TOKEN: tokens.get("id_token", ""),
                        CONF_EXPIRES_AT: tokens["expires_at"],
                    }
                    self._organisations = organisations
                    return await self.async_step_select_organisation()

            except InvalidCredentialsError:
                errors["base"] = "invalid_auth"
            except RateLimitError:
                errors["base"] = "rate_limited"
            except AuthenticationError:
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during authentication")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=USER_SCHEMA,
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

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication when tokens expire."""
        return await self.async_step_reauth_confirm()

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
            except InvalidCredentialsError:
                errors["base"] = "invalid_auth"
            except RateLimitError:
                errors["base"] = "rate_limited"
            except AuthenticationError:
                errors["base"] = "cannot_connect"
            except aiohttp.ClientError:
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
