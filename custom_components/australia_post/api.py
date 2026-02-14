"""Australia Post MyPost Business API client."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .auth import AusPostAuth, _mask_token
from .const import API_BASE_URL, API_ORG_TYPES, API_PARTNER_ID
from .exceptions import ApiError, AuthenticationError, RateLimitError
from .models import Organisation, Shipment, ShipmentsResponse

_LOGGER = logging.getLogger(__name__)


class AusPostApiClient:
    """API client for Australia Post MyPost Business."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        auth: AusPostAuth,
        account_number: str | None = None,
    ) -> None:
        """Initialise the API client.

        Args:
            session: aiohttp session for making requests.
            auth: Auth handler for obtaining access tokens.
            account_number: Account number for API calls (from organisation).
        """
        self._session = session
        self._auth = auth
        self._account_number = account_number

    @property
    def account_number(self) -> str | None:
        """Return the current account number."""
        return self._account_number

    @account_number.setter
    def account_number(self, value: str) -> None:
        """Set the account number."""
        self._account_number = value

    async def _async_get_headers(self) -> dict[str, str]:
        """Build authenticated request headers."""
        access_token = await self._auth.async_get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "auspost-partner-id": API_PARTNER_ID,
            "organisation-types": API_ORG_TYPES,
            "Accept": "application/json",
        }
        if self._account_number:
            headers["account-number"] = self._account_number
        return headers

    async def _async_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
    ) -> Any:
        """Make an authenticated API request.

        Args:
            method: HTTP method.
            path: API path (appended to base URL).
            params: Optional query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limited.
            ApiError: For other API errors.
        """
        url = f"{API_BASE_URL}{path}"
        headers = await self._async_get_headers()

        _LOGGER.debug(
            "API request: %s %s (token=%s)",
            method,
            path,
            _mask_token(headers.get("Authorization", "")[-20:]),
        )

        try:
            async with self._session.request(
                method, url, headers=headers, params=params
            ) as resp:
                if resp.status == 401:
                    raise AuthenticationError(
                        "Access token expired or invalid"
                    )
                if resp.status == 403:
                    raise AuthenticationError(
                        "Access denied to Australia Post API"
                    )
                if resp.status == 429:
                    raise RateLimitError("Australia Post API rate limit exceeded")
                if resp.status >= 500:
                    raise ApiError(
                        f"Australia Post API server error (HTTP {resp.status})"
                    )
                if resp.status != 200:
                    text = await resp.text()
                    raise ApiError(
                        f"API request failed (HTTP {resp.status}): {text[:200]}"
                    )
                return await resp.json()
        except aiohttp.ClientError as err:
            raise ApiError(
                f"Error communicating with Australia Post API: {err}"
            ) from err

    async def async_get_organisations(self) -> list[Organisation]:
        """Fetch organisations for the authenticated user.

        Returns:
            List of organisations with account numbers and band info.
        """
        data = await self._async_request(
            "GET", "/mypostbusiness-organisation/v1/organisations"
        )

        _LOGGER.debug("Raw organisations response: %s", data)

        # Response may be a list directly or wrapped in an "organisations" key
        org_list = data if isinstance(data, list) else data.get("organisations", [data])

        organisations = []
        for org_data in org_list:
            if isinstance(org_data, dict):
                organisations.append(Organisation.from_dict(org_data))

        _LOGGER.debug("Fetched %d organisation(s)", len(organisations))
        return organisations

    async def async_get_shipments(
        self,
        statuses: list[str] | None = None,
        offset: int = 0,
        number_of_shipments: int = 50,
    ) -> ShipmentsResponse:
        """Fetch shipments with optional status filter.

        Args:
            statuses: List of status strings to filter by.
            offset: Pagination offset.
            number_of_shipments: Number of shipments per page.

        Returns:
            ShipmentsResponse with shipments and pagination info.
        """
        params: dict[str, str] = {
            "offset": str(offset),
            "number_of_shipments": str(number_of_shipments),
        }
        if statuses:
            params["status"] = ",".join(statuses)

        data = await self._async_request(
            "GET", "/shipping/v1/shipments", params=params
        )

        response = ShipmentsResponse.from_dict(data)
        _LOGGER.debug(
            "Fetched %d shipment(s) (offset=%d, total=%d)",
            len(response.shipments),
            offset,
            response.pagination.total_number_of_records,
        )
        return response

    async def async_get_all_active_shipments(self) -> list[Shipment]:
        """Fetch all shipments with active (non-terminal) statuses.

        Auto-paginates until all active shipments are retrieved.

        Returns:
            List of all active shipments.
        """
        active_statuses = [
            "INITIATED",
            "TRACK_SHIPMENT",
            "IN_TRANSIT",
            "AWAITING_COLLECTION",
            "HELD_BY_COURIER",
            "POSSIBLE_DELAY",
            "UNSUCCESSFUL_PICKUP",
        ]

        all_shipments: list[Shipment] = []
        offset = 0
        page_size = 50

        while True:
            response = await self.async_get_shipments(
                statuses=active_statuses,
                offset=offset,
                number_of_shipments=page_size,
            )
            all_shipments.extend(response.shipments)
            if len(response.shipments) < page_size:
                break
            offset += page_size

        _LOGGER.debug("Fetched %d total active shipment(s)", len(all_shipments))
        return all_shipments
