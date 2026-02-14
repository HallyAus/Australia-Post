"""Australia Post MyPost Business integration for Home Assistant."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AusPostApiClient
from .auth import AusPostAuth
from .const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_ACCOUNT_NUMBER,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_EXPIRES_AT,
    CONF_PARTNERS_TOKEN,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)
from .coordinator import AusPostDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Australia Post from a config entry."""
    session = async_get_clientsession(hass)

    # Initialise auth based on the authentication method
    auth = AusPostAuth(session)
    auth_method = entry.data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)

    if auth_method == AUTH_METHOD_TOKEN:
        # Partners token: static bearer credential, never expires
        auth.set_partners_token(entry.data[CONF_PARTNERS_TOKEN])
    elif auth_method == AUTH_METHOD_API_KEY:
        # API credentials: use client_credentials for automatic token refresh
        auth.set_client_credentials(
            entry.data[CONF_CLIENT_ID],
            entry.data[CONF_CLIENT_SECRET],
        )
        auth.restore_tokens(
            access_token=entry.data[CONF_ACCESS_TOKEN],
            refresh_token="",
            expires_at=entry.data[CONF_EXPIRES_AT],
        )
    else:
        # Email + password: use stored refresh_token
        auth.restore_tokens(
            access_token=entry.data[CONF_ACCESS_TOKEN],
            refresh_token=entry.data.get(CONF_REFRESH_TOKEN, ""),
            expires_at=entry.data[CONF_EXPIRES_AT],
        )

    # Create API client — fall back to extracting account from JWT if needed
    account_number = entry.data.get(CONF_ACCOUNT_NUMBER)
    if not account_number and entry.data.get(CONF_ACCESS_TOKEN):
        account_number = AusPostAuth.extract_account_from_token(
            entry.data[CONF_ACCESS_TOKEN]
        )
        _LOGGER.debug(
            "Account number not in config, extracted from JWT: %s",
            account_number,
        )

    api_client = AusPostApiClient(
        session=session,
        auth=auth,
        account_number=account_number,
    )

    # Create coordinator
    coordinator = AusPostDataUpdateCoordinator(
        hass=hass,
        api_client=api_client,
        auth=auth,
        config_entry=entry,
    )

    # Fetch initial data (raises ConfigEntryNotReady on failure)
    await coordinator.async_config_entry_first_refresh()

    # Store coordinator for platform access
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Forward setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
