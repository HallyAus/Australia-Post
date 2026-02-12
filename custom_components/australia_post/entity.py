"""Base entity for the Australia Post integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_ACCOUNT_NUMBER, CONF_ORGANISATION_NAME, DOMAIN
from .coordinator import AusPostDataUpdateCoordinator


class AusPostEntity(CoordinatorEntity[AusPostDataUpdateCoordinator]):
    """Base entity for Australia Post."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AusPostDataUpdateCoordinator,
        unique_id_suffix: str,
    ) -> None:
        """Initialise the entity."""
        super().__init__(coordinator)
        account_number = coordinator.config_entry.data.get(
            CONF_ACCOUNT_NUMBER, ""
        )
        self._attr_unique_id = f"{account_number}_{unique_id_suffix}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for grouping entities."""
        account_number = self.coordinator.config_entry.data.get(
            CONF_ACCOUNT_NUMBER, ""
        )
        org_name = self.coordinator.config_entry.data.get(
            CONF_ORGANISATION_NAME, "MyPost Business"
        )
        return DeviceInfo(
            identifiers={(DOMAIN, account_number)},
            name=f"Australia Post - {org_name}",
            manufacturer="Australia Post",
            model="MyPost Business",
            entry_type=DeviceEntryType.SERVICE,
        )
