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
    CONF_ACCESS_TOKEN,
    CONF_ACCOUNT_NUMBER,
    CONF_EXPIRES_AT,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)
from .coordinator import AusPostDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Australia Post from a config entry."""
    session = async_get_clientsession(hass)

    # Initialise auth with stored tokens
    auth = AusPostAuth(session)
    auth.restore_tokens(
        access_token=entry.data[CONF_ACCESS_TOKEN],
        refresh_token=entry.data[CONF_REFRESH_TOKEN],
        expires_at=entry.data[CONF_EXPIRES_AT],
    )

    # Create API client
    api_client = AusPostApiClient(
        session=session,
        auth=auth,
        account_number=entry.data.get(CONF_ACCOUNT_NUMBER),
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
