"""Diagnostics support for Australia Post integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

TO_REDACT = {
    "access_token",
    "refresh_token",
    "id_token",
    "email",
    "password",
    "account_number",
    "abn",
    "phone",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    data = coordinator.data

    diagnostics: dict[str, Any] = {
        "config_entry": async_redact_data(entry.as_dict(), TO_REDACT),
    }

    if data:
        diagnostics["shipment_count"] = len(data.shipments)
        diagnostics["status_counts"] = data.shipment_counts
        diagnostics["organisation_count"] = len(data.organisations)
    else:
        diagnostics["shipment_count"] = 0
        diagnostics["status_counts"] = {}
        diagnostics["organisation_count"] = 0

    return diagnostics
