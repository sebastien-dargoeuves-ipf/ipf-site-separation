# IP Fabric and ServiceNow Integration

This script provides a command-line interface (CLI) to integrate IP Fabric with ServiceNow. It fetches device information from both IP Fabric and ServiceNow, matches the devices based on their hostnames, and optionally updates the global and local attributes in IP Fabric.

## Requirements

- Python 3.8 or higher
- typer
- pandas
- ipfabric
- ipfabric_snow

## Installation

1. Clone the repository
2. Install the dependencies with pip:

```bash
pip install -r requirements.txt
```

## Usage

### ServiceNow info for Site Separation

Using the `snow` option, you can set up the SiteSeparation in IP Fabric to follow the location in ServiceNow. The matching will be done based on the hostname.

To run the script in dry run mode (default), which fetches and matches the device information but does not update IP Fabric:

```bash
python snow_site_sep.py snow
```

In dry run mode, the script saves the matched and not found devices to `matched_devices.csv` and `not_found_devices.csv` respectively.

To update the global and local attributes in IP Fabric with the matched device information:

```bash
python snow_site_sep.py snow --update-ipf
```

### CatchAll Remediation

Using the `catch_all` option, you can search within IP Fabric for devices currently assigned to `_catch_all_`, and
if the subnet of the management IP matches the IP of other devices with an allocated site, the script will update
the siteName of the devices.
If there are multiple matches, it will be listed as `_fixme_XXXX`

## Environment Variables

The script requires the following environment variables:

- `SNOW_USER`: The username for ServiceNow.
- `SNOW_PASS`: The password for ServiceNow.
- `SNOW_URL`: The URL of the ServiceNow instance.
- `IPF_URL`: The URL of the IP Fabric instance.
- `IPF_TOKEN`: The API token for IP Fabric.
- `IPF_SNAPSHOT`: The snapshot ID in IP Fabric. Defaults to `$last`.

You can set these environment variables in a `.env` file in the same directory as the script. The script uses the `python-dotenv` package to load these environment variables.

## Logging

The script logs its operations to the console. You can customize the logging behavior by modifying the `logger` configuration in the script.
