# IP Fabric -- Site Separation and Attribute Manager

This script provides a command-line interface (CLI) to help manage the Site Separation and Attributes in IP Fabric. The main functionality includes:

1. `snow`: This command fetches device information from both IP Fabric and ServiceNow, matches the devices based on their hostnames, and optionally updates the global and local attributes in IP Fabric.
2. `catch_all`: This command checks for all devices in a specific "catch-all" site name and tries to match those devices with devices already assigned to a site, based on their login IP addresses.
3. `subnet`: This command uses a provided JSON file containing a list of dictionaries in the format `[{'subnet': 'siteName'}, ...]`. The site separation is then performed based on the match between the device login IP and the subnets from the JSON file.
4. `push`: This command takes a generated file or a manually created site separation file with the correct structure and pushes the site separation information to IP Fabric.
5. `report`: This command generates a report to help identify potential gaps in the site separation. By default, the report assigns the management subnet based on the `managedIP` table and the `loginIP` of each device, and then checks all devices within each subnet to create the `matchingSites` column. The report also offers options to perform hostname-based and connectivity matrix-based lookups to refine the site separation suggestions.

## Requirements

- ipfabric
- loguru
- pandas
- Python 3.8 or higher
- tqdm
- typer
- ipfabric_snow (only for the `snow` command)
- openpyxl (for Excel reports)
- yaspin (optional)

## Installation

1. Clone the repository
2. Install the dependencies with pip:

    ```bash
    pip install -r requirements.txt
    ```

3. Copy the environment file, and edit the variables accordingly:

    ```bash
    cp .env.sample .env
    ```

## `snow` - Build Site Separation using ServiceNow data

The `snow` option allows you to set up the Site Separation in IP Fabric to follow the location information from ServiceNow. The matching process is based on the device hostname.
To run the script in dry run mode (the default), which fetches and matches the device information without updating IP Fabric:

```bash
python site_sep.py snow
```

In dry run mode, the script saves the matched devices to `matched_devices.csv` and the not-found devices to `not_found_devices.csv`.
To update the global and local attributes in IP Fabric with the matched device information:

```bash
python site_sep.py snow --update-ipf
```

This command will update the IP Fabric data with the site separation information based on the matching with ServiceNow data.

## `catch_all` - Clean Up Devices Belonging to a Default Site, or `unknown`

The `catch_all` option helps you clean up devices that are currently assigned to the `CATCH_ALL` site, which is defined in the `modules/settings.py` file.
The script searches within IP Fabric for devices assigned to the `CATCH_ALL` site. It then checks the subnet of the management IP, based on the `SEARCH_NETWORK_PREFIX` prefix length, and attempts to match it with the subnet of `other` devices that have an allocated site.
If a matching subnet is found, the script will update the `siteName` of the devices. If there are no matches or multiple matches, the device will be listed with the `PREFIX_FIXME` tag.
To run the script in dry run mode:

```bash
python site_sep.py catch_all
```

In dry run mode, the script saves the results to `catch_all_remediation.csv`.
To update the global and/or local attributes in IP Fabric with the matched device information:

```bash
python site_sep.py catch_all --update-ipf
```

This command will update the IP Fabric data with the corrected site separation information for the devices that were previously assigned to the `CATCH_ALL` site.

## `subnet` - Build Attributes (by default siteName) based on Subnet Data Provided in a JSON File

The `subnet` option allows you to search for all devices with a login IP and assign them an attribute based on subnet information provided in a source file.
By default, 'siteName' is the attribute that will be updated.

```bash
python site_sep.py subnet <name-of-subnet-file.json>
python site_sep.py subnet <name-of-subnet-file.json> -a <attribute_key>
```

In dry run mode, the script saves the results to `update_attributes_from_subnet.csv`.

To update the global and/or local attributes in IP Fabric with the matched device information, use the following command:

```bash
python site_sep.py subnet <name-of-subnet-file.json> -a <attribute_key> --update-ipf -a
```

The source file needs to be constructed like this, with the `value` you want to give to the `attribute_key` specified in the command above:

```json
[
    {
        "value": "SiteA",
        "subnet": "10.194.56.64/28"
    },
    {
        "value": "SiteB",
        "subnet": "10.194.56.80/28"
    },
    {
        "value": "SiteC",
        "subnet": "10.194.56.96/28"
    }
]
```

## `push` - Update Attributes Based on a CSV or Excel File

```bash
python site_sep.py push <site_separation_to_push.csv>
```

By default, only the `siteName` will be updated. You can also specify which columns to use to create multiple attributes. The attributes you specify must match the names of the columns (case-sensitive):

```bash
python site_sep.py push <site_separation_to_push.csv> -a siteName -a ServiceNowLocation -a Customer -a Building -a Region
```

This command will update the following attributes based on the corresponding columns in the provided CSV or Excel file:

- siteName
- ServiceNowLocation
- Customer
- Building
- Region

The script will use the data from the specified file to update the Attributes settings accordingly.

## `report` - Create a report to find potential gaps in the Site Separation

- **Subnet-based Site Assignment**: By default, the site separation report assigns the management subnet based on the `managedIP` table and the `loginIP` of each device. The analysis then checks all devices within each subnet to create the `matchingSites` column. If a site in that list contains more than 50% of the devices in the subnet, it will be selected as the new `siteName`.

    ```bash
    python site_sep.py report <output_report_filename>
    ```

    | hostname | loginIp | sn         | currentSiteName | net        | matchingSites                                                                      | suggestedFinalSite | suggested eq IPF Site | finalSite |
    |----------|---------|------------|-----------------|------------|------------------------------------------------------------------------------------|--------------------|-----------------------|-----------|
    | device1  | 1.1.1.1 | ABCD1234EF | site2           | 1.1.1.0/28 | {'site1': {'count': 9, 'percent': 90.00}, 'site2': {'count': 1, 'percent': 10.00}} | site1              | FALSE                 |           |
    | device2  | 1.1.1.2 | ABCD1234GH | site1           | 1.1.1.0/28 | {'site1': {'count': 9, 'percent': 90.00}, 'site2': {'count': 1, 'percent': 10.00}} | site1              | TRUE                  |           |

- **Hostname-based Site Assignment (`--hostname-match` or `-hm`)**: This option performs a lookup based on the hostname. The script will try to find a match for devices with similar start of their hostname and collect the siteName information for the matching devices.
The hostname match removes 1 character of a device, searches for any other devices matching, and repeats until it has 5 (or the settings variable: `MIN_LENGTH_PARTIAL_HOSTNAME`) characters left. Based on this, it collects the list of `siteName` based on the matching hostname, up to 4 (or `MAX_ENTRIES_SITE_LIST`). If there is only one unique site, it will use this.

    ```bash
    python site_sep.py report --hostname-match <output_report_filename>
    ```

- **Connectivity Matrix-based Site Assignment (`--connectivity-matrix-match` or `-cmm`)**: This method checks the connectivity matrix table for L1 and L2 connections with other devices, gets the `siteName` of the neighbor, and builds the list of matching sites. If it's unique, it will use this.

- **Recheck Site Separation (`--recheck-site-sep` or `-r` option)**: This option allows a second pass before generating the suggested `siteName`, based on the data calculated. This means that once the initial report is generated using the subnet matching (and optionally the hostname and connectivity matrix matches), it analyzes the new data to see if it can now map more devices to their `siteName`.

## Usage

### Example: generating a report

```bash
# Generate a report based on the subnet matching, plus showing the hostname match and connectivity matrix match if found.
python3 site_sep.py report --hostname-match --connectivity-matrix-match --recheck-site-sep report_full_with_recheck
# is the same as:
python3 site_sep.py report -hm -cmm -r report_full_with_recheck

# the output will be in ./report/report_full_with_recheck.xlsx

# now to push these new attributes, you can use the push command:

python3 site_sep.py push report/report_full_with_recheck.xlsx
# or if you have a specific column you want to use:
python3 site_sep.py push report/report_full_with_recheck.xlsx -a suggestedFinalSite
```

### Example: updating global attributes, using a report generated from the `push`

```bash
╰─❯ python site_sep.py push report/2024-10-01-push.xlsx 
2024-10-01 14:27:02.978 | INFO     | __main__:logging_configuration:45 - ---- NEW EXECUTION OF SCRIPT ----
2024-10-01 14:27:03.082 | INFO     | modules.utils:read_site_sep_file:299 - File `report/2024-10-01-push.xlsx` loaded (234 entries)
(Recommended) Do you want to update global attributes? [Y/n]: y
(Optional) Do you want to update local attributes? It will recalculate siteSeparation for snapshot `$last` [y/N]: n
Do you want to clear the existing global attributes?
 /!\ YOU WILL LOSE ALL PREVIOUSLY ADDED ATTRIBUTES /!\ [y/N]: n
2024-10-01 14:29:00.956 | INFO     | modules.f_ipf:update_attributes:183 - Global Attributes '['siteName']' updated! (234 entries)
2024-10-01 14:29:00.965 | INFO     | __main__:push:160 - 'Push Site Separation from file' task completed
```

## Environment Variables

The script requires the following environment variables, which you will find in the `.env.sample` file:

- `SNOW_USER`: The username for ServiceNow.
- `SNOW_PASS`: The password for ServiceNow.
- `SNOW_URL`: The URL of the ServiceNow instance.
- `IPF_URL`: The URL of the IP Fabric instance.
- `IPF_TOKEN`: The API token for IP Fabric.
- `IPF_SNAPSHOT`: The snapshot ID in IP Fabric. It defaults to `$last`, but you can change it by specifying the ID of the desired snapshot.

You can set these environment variables in a `.env` file in the same directory as the script.

Additionally, you can check the `modules/settings.py` file for any other advanced variables that you may need to configure.

## Logging

The script logs its operations to the console and in the `logs/` folder.

## Support

If you have any questions, suggestions, or issues, please feel free to submit a pull request or open an issue on the project's repository.

## Contributions

We welcome contributions to the project. If you would like to contribute, please submit a pull request or open an issue on the project's GitHub repository.
