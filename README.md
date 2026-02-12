# Australia Post MyPost Business for Home Assistant

A custom [Home Assistant](https://www.home-assistant.io/) integration that connects to your [Australia Post MyPost Business](https://auspost.com.au/mypost-business) account to track parcel shipments and organisation details.

## Features

- Track all active shipments with real-time status updates
- Individual sensor per active shipment with full tracking details
- Aggregate sensors for shipment counts by status
- Organisation and pricing band information
- Automatic token refresh (no need to re-enter credentials)
- Secure credential handling (password never stored, only OAuth tokens)

## Prerequisites

- A Home Assistant instance (version 2024.1.0 or later)
- An Australia Post MyPost Business account with email and password login

## Installation

### HACS (Recommended)

1. Open HACS in your Home Assistant instance
2. Click the three-dot menu in the top right and select **Custom repositories**
3. Add `https://github.com/HallyAus/Australia-Post` as a custom repository with category **Integration**
4. Search for "Australia Post" in HACS and install it
5. Restart Home Assistant

### Manual

1. Download the `custom_components/australia_post` folder from this repository
2. Copy it into your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant

## Configuration

1. Go to **Settings** > **Devices & Services** > **Add Integration**
2. Search for **Australia Post MyPost Business**
3. Enter your MyPost Business email and password
4. If you have multiple organisations, select which one to track
5. The integration will authenticate and begin fetching your shipment data

Your password is used only for the initial login and is **not stored**. The integration uses OAuth tokens for ongoing access.

## Sensors

### Aggregate Sensors

| Sensor | Description | Attributes |
|--------|-------------|------------|
| Active Shipments | Count of all non-delivered shipments | Breakdown by status (in transit, awaiting collection, etc.) |
| Delivered Shipments | Count of recently delivered shipments | - |
| Organisation Band | Your current Australia Post pricing band | Organisation name, account number |

### Per-Shipment Sensors

A dynamic sensor is created for each active shipment. The sensor state is the current shipment status (e.g. "Initiated", "In Transit", "Delivered").

**Attributes include:**
- Shipment ID and reference
- Customer reference and order ID
- Recipient name, suburb, state, postcode
- Sender name and references
- Tracking IDs and consignment IDs
- Creation and last modified dates
- Total cost and item count

## Shipment Statuses

| Status | Description |
|--------|-------------|
| Initiated | Label created, not yet lodged |
| In Transit | Parcel is being transported |
| Awaiting Collection | Ready for pickup |
| Held by Courier | With delivery driver |
| Delivered | Successfully delivered |
| Possible Delay | Potential delivery delay |
| Unsuccessful Pickup | Pickup attempt failed |
| Cannot Be Delivered | Delivery not possible |
| Cancelled | Shipment cancelled |
| Completed | Fully completed |

## Data Refresh

The integration polls the Australia Post API every **15 minutes**. Access tokens are refreshed automatically before they expire (tokens last approximately 30 minutes).

## Re-authentication

If your refresh token expires or is revoked, Home Assistant will prompt you to re-authenticate. Go to **Settings** > **Devices & Services**, find the Australia Post integration, and follow the re-authentication flow.

## Security

This integration follows security best practices:

- Your password is used only during initial setup and is **never stored**
- Only OAuth tokens (access token, refresh token) are persisted in Home Assistant's secure config storage
- All tokens are masked in log output
- Diagnostics data redacts sensitive fields (tokens, email, account numbers, phone numbers)
- Authentication uses PKCE (Proof Key for Code Exchange) for secure token exchange

## Known Limitations

- **MFA/Two-Factor Authentication** is not currently supported. If your account has MFA enabled, the integration may not be able to authenticate.
- **CAPTCHA challenges** may be presented by Australia Post's login system after repeated login attempts. If this occurs, wait a few minutes and try again.
- Only **MyPost Business** accounts are supported (not personal MyPost accounts).
- The integration shows shipment data from the MyPost Business sending/tracking dashboard.

## Troubleshooting

**"Invalid email or password" error during setup:**
Verify your credentials by logging in at [MyPost Business](https://auspost.com.au/mypost-business). Ensure you're using your MyPost Business email, not a personal MyPost account.

**"Unable to connect to Australia Post" error:**
Check your internet connection. Australia Post's API may be temporarily unavailable. Try again in a few minutes.

**"Too many login attempts" error:**
You've been rate-limited. Wait 5-10 minutes before trying again.

**Sensors show "unavailable":**
This usually means the authentication token has expired. Check for a re-authentication prompt in Settings > Devices & Services.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This integration is not affiliated with, endorsed by, or connected to Australia Post. It is an independent, community-developed project. Use at your own risk.
