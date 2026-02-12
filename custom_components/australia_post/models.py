"""Data models for the Australia Post MyPost Business integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Organisation:
    """Australia Post MyPost Business organisation."""

    organisation_id: str
    name: str
    account_number: str
    abn: str | None = None
    band: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Organisation:
        """Create an Organisation from API response dict."""
        return cls(
            organisation_id=data.get("organisation_id", ""),
            name=data.get("name", ""),
            account_number=data.get("account_number", ""),
            abn=data.get("abn"),
            band=data.get("band"),
        )


@dataclass
class TrackingDetails:
    """Tracking details for a shipment item."""

    article_id: str
    consignment_id: str
    barcode_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrackingDetails:
        """Create TrackingDetails from API response dict."""
        return cls(
            article_id=data.get("article_id", ""),
            consignment_id=data.get("consignment_id", ""),
            barcode_id=data.get("barcode_id"),
        )


@dataclass
class ItemSummary:
    """Summary information for a shipment item."""

    total_cost: float
    total_cost_ex_gst: float
    total_gst: float
    status: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ItemSummary:
        """Create ItemSummary from API response dict."""
        return cls(
            total_cost=data.get("total_cost", 0.0),
            total_cost_ex_gst=data.get("total_cost_ex_gst", 0.0),
            total_gst=data.get("total_gst", 0.0),
            status=data.get("status", ""),
        )


@dataclass
class ShipmentItem:
    """A single item (parcel) within a shipment."""

    item_id: str
    item_reference: str
    weight: float | None = None
    height: float | None = None
    length: float | None = None
    width: float | None = None
    product_id: str = ""
    tracking_details: TrackingDetails | None = None
    item_summary: ItemSummary | None = None
    contains_dangerous_goods: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShipmentItem:
        """Create a ShipmentItem from API response dict."""
        tracking = None
        if "tracking_details" in data:
            tracking = TrackingDetails.from_dict(data["tracking_details"])

        summary = None
        if "item_summary" in data:
            summary = ItemSummary.from_dict(data["item_summary"])

        return cls(
            item_id=data.get("item_id", ""),
            item_reference=data.get("item_reference", ""),
            weight=data.get("weight"),
            height=data.get("height"),
            length=data.get("length"),
            width=data.get("width"),
            product_id=data.get("product_id", ""),
            tracking_details=tracking,
            item_summary=summary,
            contains_dangerous_goods=data.get("contains_dangerous_goods", False),
        )


@dataclass
class Address:
    """Address information."""

    name: str = ""
    lines: list[str] = field(default_factory=list)
    suburb: str = ""
    postcode: str = ""
    state: str = ""
    country: str = ""
    email: str = ""
    phone: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Address:
        """Create an Address from API response dict."""
        return cls(
            name=data.get("name", ""),
            lines=data.get("lines", []),
            suburb=data.get("suburb", ""),
            postcode=data.get("postcode", ""),
            state=data.get("state", ""),
            country=data.get("country", ""),
            email=data.get("email", ""),
            phone=data.get("phone", ""),
        )


@dataclass
class ShipmentSummary:
    """Summary information for a shipment."""

    total_cost: float
    total_cost_ex_gst: float
    total_gst: float
    status: str
    number_of_items: int
    tracking_summary: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShipmentSummary:
        """Create ShipmentSummary from API response dict."""
        return cls(
            total_cost=data.get("total_cost", 0.0),
            total_cost_ex_gst=data.get("total_cost_ex_gst", 0.0),
            total_gst=data.get("total_gst", 0.0),
            status=data.get("status", ""),
            number_of_items=data.get("number_of_items", 0),
            tracking_summary=data.get("tracking_summary", {}),
        )


@dataclass
class Shipment:
    """A shipment containing one or more items."""

    shipment_id: str
    shipment_reference: str = ""
    shipment_creation_date: str = ""
    shipment_modified_date: str = ""
    customer_reference_1: str = ""
    sender_references: list[str] = field(default_factory=list)
    order_id: str = ""
    from_address: Address = field(default_factory=Address)
    to_address: Address = field(default_factory=Address)
    items: list[ShipmentItem] = field(default_factory=list)
    shipment_summary: ShipmentSummary | None = None

    @property
    def status(self) -> str:
        """Return the overall shipment status."""
        if self.shipment_summary:
            return self.shipment_summary.status
        return ""

    @property
    def tracking_ids(self) -> list[str]:
        """Return all article IDs for tracking."""
        return [
            item.tracking_details.article_id
            for item in self.items
            if item.tracking_details
        ]

    @property
    def consignment_ids(self) -> list[str]:
        """Return all consignment IDs."""
        return [
            item.tracking_details.consignment_id
            for item in self.items
            if item.tracking_details
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Shipment:
        """Create a Shipment from API response dict."""
        from_addr = Address()
        if "from" in data:
            from_addr = Address.from_dict(data["from"])

        to_addr = Address()
        if "to" in data:
            to_addr = Address.from_dict(data["to"])

        items = [ShipmentItem.from_dict(item) for item in data.get("items", [])]

        summary = None
        if "shipment_summary" in data:
            summary = ShipmentSummary.from_dict(data["shipment_summary"])

        return cls(
            shipment_id=data.get("shipment_id", ""),
            shipment_reference=data.get("shipment_reference", ""),
            shipment_creation_date=data.get("shipment_creation_date", ""),
            shipment_modified_date=data.get("shipment_modified_date", ""),
            customer_reference_1=data.get("customer_reference_1", ""),
            sender_references=data.get("sender_references", []),
            order_id=data.get("order_id", ""),
            from_address=from_addr,
            to_address=to_addr,
            items=items,
            shipment_summary=summary,
        )


@dataclass
class Pagination:
    """Pagination information from API response."""

    total_number_of_records: int = 0
    number_of_records_per_page: int = 10
    current_page_number: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Pagination:
        """Create Pagination from API response dict."""
        return cls(
            total_number_of_records=data.get("total_number_of_records", 0),
            number_of_records_per_page=data.get("number_of_records_per_page", 10),
            current_page_number=data.get("current_page_number", 1),
        )


@dataclass
class ShipmentsResponse:
    """Response from the shipments endpoint."""

    shipments: list[Shipment]
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShipmentsResponse:
        """Create ShipmentsResponse from API response dict."""
        shipments = [Shipment.from_dict(s) for s in data.get("shipments", [])]
        pagination = Pagination()
        if "pagination" in data:
            pagination = Pagination.from_dict(data["pagination"])
        return cls(shipments=shipments, pagination=pagination)


@dataclass
class AusPostData:
    """Container for all data fetched by the coordinator."""

    organisations: list[Organisation]
    shipments: list[Shipment]
    shipment_counts: dict[str, int] = field(default_factory=dict)
