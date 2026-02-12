"""DataUpdateCoordinator for Australia Post MyPost Business."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AusPostApiClient
from .auth import AusPostAuth
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_EXPIRES_AT,
    CONF_REFRESH_TOKEN,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .exceptions import ApiError, AuthenticationError, RateLimitError, TokenExpiredError
from .models import AusPostData

_LOGGER = logging.getLogger(__name__)


class AusPostDataUpdateCoordinator(DataUpdateCoordinator[AusPostData]):
    """Coordinator to manage fetching Australia Post data."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        api_client: AusPostApiClient,
        auth: AusPostAuth,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialise the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=DEFAULT_SCAN_INTERVAL),
            always_update=False,
        )
        self.api_client = api_client
        self.auth = auth
        self.config_entry = config_entry

    async def _async_update_data(self) -> AusPostData:
        """Fetch data from the Australia Post API.

        Called by the DataUpdateCoordinator on the configured interval.
        """
        try:
            # Fetch organisations for band info
            organisations = await self.api_client.async_get_organisations()

            # Fetch all active shipments (auto-paginated)
            active_shipments = await self.api_client.async_get_all_active_shipments()

            # Fetch recent terminal shipments for context
            terminal_response = await self.api_client.async_get_shipments(
                statuses=["DELIVERED", "COMPLETED", "CANCELLED"],
                offset=0,
                number_of_shipments=20,
            )
            all_shipments = active_shipments + terminal_response.shipments

            # Compute status counts
            counts: dict[str, int] = {}
            for shipment in all_shipments:
                status = shipment.status
                if status:
                    counts[status] = counts.get(status, 0) + 1

            # Persist updated tokens to config entry if they changed
            await self._async_update_tokens_if_changed()

            return AusPostData(
                organisations=organisations,
                shipments=all_shipments,
                shipment_counts=counts,
            )

        except TokenExpiredError as err:
            raise ConfigEntryAuthFailed(
                "Authentication tokens expired. Please re-authenticate."
            ) from err

        except AuthenticationError as err:
            raise ConfigEntryAuthFailed(str(err)) from err

        except RateLimitError as err:
            raise UpdateFailed(
                f"Rate limited by Australia Post API: {err}"
            ) from err

        except ApiError as err:
            raise UpdateFailed(
                f"Error fetching Australia Post data: {err}"
            ) from err

        except aiohttp.ClientError as err:
            raise UpdateFailed(
                f"Error communicating with Australia Post API: {err}"
            ) from err

    async def _async_update_tokens_if_changed(self) -> None:
        """Persist refreshed tokens back to the config entry."""
        current_token = self.config_entry.data.get(CONF_ACCESS_TOKEN)
        new_token = self.auth.access_token

        if new_token and new_token != current_token:
            new_data: dict[str, Any] = {
                **self.config_entry.data,
                CONF_ACCESS_TOKEN: self.auth.access_token,
                CONF_REFRESH_TOKEN: self.auth.refresh_token,
                CONF_EXPIRES_AT: self.auth.expires_at,
            }
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )
            _LOGGER.debug("Updated stored tokens in config entry")
