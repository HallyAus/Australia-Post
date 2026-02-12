"""Sensor platform for Australia Post MyPost Business."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from .const import ACTIVE_STATUSES, CONF_ACCOUNT_NUMBER, DOMAIN
from .coordinator import AusPostDataUpdateCoordinator
from .entity import AusPostEntity
from .models import AusPostData, Shipment


@dataclass(frozen=True, kw_only=True)
class AusPostSensorEntityDescription(SensorEntityDescription):
    """Describe an Australia Post sensor."""

    value_fn: Callable[[AusPostData], StateType]
    attr_fn: Callable[[AusPostData], dict[str, Any]] | None = None


def _count_active(data: AusPostData) -> int:
    """Count shipments with active statuses."""
    return sum(1 for s in data.shipments if s.status in ACTIVE_STATUSES)


def _count_delivered(data: AusPostData) -> int:
    """Count delivered shipments."""
    return sum(1 for s in data.shipments if s.status == "Delivered")


def _active_attributes(data: AusPostData) -> dict[str, Any]:
    """Build attributes for the active shipments sensor."""
    counts: dict[str, int] = {}
    for shipment in data.shipments:
        status = shipment.status
        if status in ACTIVE_STATUSES:
            counts[status] = counts.get(status, 0) + 1

    return {
        "in_transit": counts.get("IN_TRANSIT", 0),
        "awaiting_collection": counts.get("AWAITING_COLLECTION", 0),
        "initiated": counts.get("INITIATED", 0),
        "held_by_courier": counts.get("HELD_BY_COURIER", 0),
        "possible_delay": counts.get("POSSIBLE_DELAY", 0),
        "track_shipment": counts.get("TRACK_SHIPMENT", 0),
        "unsuccessful_pickup": counts.get("UNSUCCESSFUL_PICKUP", 0),
        "status_counts": data.shipment_counts,
    }


def _org_band_value(data: AusPostData) -> StateType:
    """Return the organisation band."""
    if data.organisations:
        return data.organisations[0].band
    return None


def _org_band_attributes(data: AusPostData) -> dict[str, Any]:
    """Build attributes for the organisation band sensor."""
    if not data.organisations:
        return {}
    org = data.organisations[0]
    return {
        "organisation_name": org.name,
        "account_number": org.account_number,
        "organisation_id": org.organisation_id,
        "abn": org.abn,
    }


SENSOR_DESCRIPTIONS: tuple[AusPostSensorEntityDescription, ...] = (
    AusPostSensorEntityDescription(
        key="active_shipments",
        translation_key="active_shipments",
        icon="mdi:package-variant",
        native_unit_of_measurement="shipments",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_count_active,
        attr_fn=_active_attributes,
    ),
    AusPostSensorEntityDescription(
        key="delivered_shipments",
        translation_key="delivered_shipments",
        icon="mdi:package-variant-closed-check",
        native_unit_of_measurement="shipments",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_count_delivered,
    ),
    AusPostSensorEntityDescription(
        key="organisation_band",
        translation_key="organisation_band",
        icon="mdi:office-building",
        value_fn=_org_band_value,
        attr_fn=_org_band_attributes,
    ),
)


class AusPostSensor(AusPostEntity, SensorEntity):
    """Australia Post aggregate sensor entity."""

    entity_description: AusPostSensorEntityDescription

    def __init__(
        self,
        coordinator: AusPostDataUpdateCoordinator,
        description: AusPostSensorEntityDescription,
    ) -> None:
        """Initialise the sensor."""
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> StateType:
        """Return the sensor value."""
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional state attributes."""
        if self.entity_description.attr_fn:
            return self.entity_description.attr_fn(self.coordinator.data)
        return None


class AusPostShipmentSensor(AusPostEntity, SensorEntity):
    """Sensor for an individual shipment."""

    _attr_icon = "mdi:package-variant"

    def __init__(
        self,
        coordinator: AusPostDataUpdateCoordinator,
        shipment: Shipment,
    ) -> None:
        """Initialise the shipment sensor."""
        super().__init__(coordinator, f"shipment_{shipment.shipment_id}")
        self._shipment_id = shipment.shipment_id
        # Use customer reference or shipment reference for the name
        ref = (
            shipment.customer_reference_1
            or shipment.shipment_reference
            or shipment.shipment_id
        )
        self._attr_name = f"Shipment {ref}"

    @property
    def native_value(self) -> str | None:
        """Return the shipment status."""
        shipment = self._find_shipment()
        return shipment.status if shipment else None

    @property
    def available(self) -> bool:
        """Return True if the shipment is still in the data."""
        return self.coordinator.last_update_success and self._find_shipment() is not None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return shipment details as attributes."""
        shipment = self._find_shipment()
        if not shipment:
            return {}

        attrs: dict[str, Any] = {
            "shipment_id": shipment.shipment_id,
            "shipment_reference": shipment.shipment_reference,
            "customer_reference": shipment.customer_reference_1,
            "order_id": shipment.order_id,
            "to_name": shipment.to_address.name,
            "to_suburb": shipment.to_address.suburb,
            "to_state": shipment.to_address.state,
            "to_postcode": shipment.to_address.postcode,
            "from_name": shipment.from_address.name,
            "sender_references": shipment.sender_references,
            "creation_date": shipment.shipment_creation_date,
            "modified_date": shipment.shipment_modified_date,
            "tracking_ids": shipment.tracking_ids,
            "consignment_ids": shipment.consignment_ids,
            "items_count": len(shipment.items),
        }

        if shipment.shipment_summary:
            attrs["total_cost"] = shipment.shipment_summary.total_cost
            attrs["number_of_items"] = shipment.shipment_summary.number_of_items

        return attrs

    def _find_shipment(self) -> Shipment | None:
        """Find this shipment in the coordinator data."""
        if not self.coordinator.data:
            return None
        for shipment in self.coordinator.data.shipments:
            if shipment.shipment_id == self._shipment_id:
                return shipment
        return None


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Australia Post sensors from a config entry."""
    coordinator: AusPostDataUpdateCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ]

    # Static aggregate sensors (always present)
    entities: list[SensorEntity] = [
        AusPostSensor(coordinator, description)
        for description in SENSOR_DESCRIPTIONS
    ]

    # Dynamic per-shipment sensors for active shipments
    tracked_shipment_ids: set[str] = set()
    if coordinator.data:
        for shipment in coordinator.data.shipments:
            if shipment.status in ACTIVE_STATUSES:
                entities.append(
                    AusPostShipmentSensor(coordinator, shipment)
                )
                tracked_shipment_ids.add(shipment.shipment_id)

    async_add_entities(entities)

    # Listen for coordinator updates to add new shipment sensors
    @callback
    def _async_handle_coordinator_update() -> None:
        """Add sensors for newly discovered active shipments."""
        if not coordinator.data:
            return
        new_entities: list[SensorEntity] = []
        for shipment in coordinator.data.shipments:
            if (
                shipment.status in ACTIVE_STATUSES
                and shipment.shipment_id not in tracked_shipment_ids
            ):
                tracked_shipment_ids.add(shipment.shipment_id)
                new_entities.append(
                    AusPostShipmentSensor(coordinator, shipment)
                )
        if new_entities:
            async_add_entities(new_entities)

    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_handle_coordinator_update)
    )
