# Router Cleanup

A local web UI for bulk-removing old/unwanted devices from a **Plusnet Hub Two** or **BT Home Hub 6** router's device history.

Routers using random MAC addresses (Apple Watch, iPhone Private Wi-Fi, etc.) accumulate hundreds of phantom entries over time. This tool lets you bulk-select and remove them in one go.

![screenshot placeholder](screenshot.png)

## Requirements

- [Node.js](https://nodejs.org) v16 or newer (no other dependencies)
- Plusnet Hub Two or BT Home Hub 6 router

## Usage

1. **Download** `router-cleanup.js` and `start.bat` from the [latest release](../../releases/latest)
2. Double-click **`start.bat`** — it opens your browser automatically
3. Enter your router's IP address (default `192.168.1.254`) and admin password
4. Select the devices you want to remove using the filters and checkboxes
5. Click **Remove selected** and confirm

On Mac/Linux, run directly:
```
node router-cleanup.js
```
Then open http://localhost:7823

## Features

- Login screen — no credentials stored anywhere
- Filter by: All / Inactive only / Unknown devices / Currently active
- Search by name, IP, or MAC
- Progress bar during bulk removal
- Download CSV of the current device list
- Refresh list button to re-fetch from router without restarting

## How it works

The tool runs a small HTTP server on `localhost:7823`. It communicates with your router's admin API using the same requests your browser makes when you use the router's web interface. Nothing is sent anywhere outside your local network.

## Notes

- Devices with DHCP reservations are fully cleared (both the device history entry and the reservation), otherwise the router re-adds them
- The router requires a fresh security token for each deletion, so bulk removal sends one request per device sequentially
- Apple Watch / iPhone "Private Wi-Fi Address" entries each have a unique random MAC, which is why so many accumulate

## License

MIT
