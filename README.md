# IP Fabric -- Site Separation Manager

This script provides a command-line interface (CLI) to help manage the Site Separation in IP Fabric:

- snow: fetches device information from both IP Fabric and ServiceNow, matches the devices based on their hostnames, and optionally updates the global and local attributes in IP Fabric.
- catch_all: check for all devices in a specific catch_all site name, and try to match those devices with devices already assigned to a site, based on the loginIp.
- subnet: using on a provided JSON file containing a list of dictionnary, like this `[{'subnet': 'siteName'}, ...]`, the site separation will be done based on the match between loginIP and the subnets from the JSON file
- push: takes one of the generated file, or aa manually created site with the correct structure, and push this as a site separation.

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

### CatchAll Remediation (no ServiceNow information required)

Using the `catch_all` option, you can search within IP Fabric for devices currently assigned to the `CATCH_ALL` site.
If the subnet, based on `SEARCH_NETWORK_PREFIX` prefix length, of the management IP matches the subnet of other devices with an allocated site, the script will update the siteName of the devices.
If there are none or multiple matches, it will be listed with the `PREFIX_FIXME`

```bash
python snow_site_sep.py catch_all
```

In dry run mode, the script saves the result to `catch_all_remediation.csv`.

To update the global and/or local attributes in IP Fabric with the matched device information:

```bash
python snow_site_sep.py catch_all --update-ipf
```

### Use Subnet matching based on source file to define siteSparation

Using the subnet option, you can search for all devices with a login IP. If this IP is part of a subnet provided in a source file, the script will assign the device to the matching site based on the information in the file.

```bash
python snow_site_sep.py subnet <name-of-subnet-file.json>
```

In dry run mode, the script saves the result to `subnets_site_separation.csv`.

To update the global and/or local attributes in IP Fabric with the matched device information:

```bash
python snow_site_sep.py subnet <name-of-subnet-file.json> --update-ipf
```

The source file needs to be constructed like this:

```json
[
    {
        "name": "SiteA",
        "subnet": "10.194.56.64/28"
    },
    {
        "name": "SiteB",
        "subnet": "10.194.56.80/28"
    },
    {
        "name": "SiteC",
        "subnet": "10.194.56.96/28"
    }
]
```

### Use push to build site separation based on a csv file

```bash
python snow_site_sep.py push <site_separation_to_push.csv>
```

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
