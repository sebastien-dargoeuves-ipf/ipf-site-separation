# IP Fabric and Site Separation

This script provides a command-line interface (CLI) to build Site Separation in IP Fabric, based on the loginIP of all IP Fabric's devices.

## Requirements

- Python 3.8 or higher
- typer
- pandas
- ipfabric

## Installation

1. Clone the repository
2. Install the dependencies with pip:

```bash
pip install -r requirements.txt
```

## Usage

### Use Subnet matching based on source file to define siteSparation

Using the subnet option, you can search for all devices with a login IP. If this IP is part of a subnet provided in a source file, the script will assign the device to the matching site based on the information in the file.

```bash
python snow_site_sep.py subnet <name-of-subnet-file.json>
```

In dry run mode, the script saves the result to `catch_all_remediation.csv`.

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

## Environment Variables

The script requires the following environment variables:

- `IPF_URL`: The URL of the IP Fabric instance.
- `IPF_TOKEN`: The API token for IP Fabric.
- `IPF_SNAPSHOT`: The snapshot ID in IP Fabric. Defaults to `$last`.

You can set these environment variables in a `.env` file in the same directory as the script. The script uses the `python-dotenv` package to load these environment variables.

## Logging

The script logs its operations to the console. You can customize the logging behavior by modifying the `logger` configuration in the script.
