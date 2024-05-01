import ipaddress
import json
import os
import sys
from typing import Union

import numpy as np
import pandas as pd
import typer
from loguru import logger

REPORT_COLUMNS = [
    "hostname",
    "loginIp",
    "sn",
    "net",
    "IPFSiteName",
    "#1",
    "matching all sites (subnet)",
    "matching sites (subnet)",
    "site based on subnet",
    "site based on subnet eq IPFSiteName",
    "#2",
    "matching sites (hostname)",
    "site based on hostname",
    "site based on hostname eq IPFSiteName",
    "#3",
    "matching sites (c_matrix)",
    "site based on c_matrix",
    "site based on c_matrix eq IPFSiteName",
    "#4",
    "siteName-firstpass",
    "siteName",
]

def check_host_bits(ip_with_subnet):
    """
    Check if the host bits are set in the IP address.
    Returns True if no host bits are set, False otherwise.
    """
    if ip_with_subnet is None:
        return False
    network = ipaddress.ip_network(ip_with_subnet, strict=False)

    actual_network_address = network.network_address

    if ipaddress.ip_address(ip_with_subnet.split("/")[0]) != actual_network_address:
        logger.warning(
            f"Host bits set: {ip_with_subnet} should be {actual_network_address}/{network.prefixlen}"
        )
        return False
    else:
        return True


def search_site(
    ip: str,
    all_devices: list,
    catch_all_str: str,
    search_network_prefix: int,
    multi_site_str_limit: int,
    prefix_fixme: str,
) -> str:
    """
    Returns the site name associated with the given IP address.

    Args:
        ipf: An instance of IPFClient used to query the inventory.
        ip: The IP address to search for.

    Returns:
        The name of the site associated with the IP address.

    Examples:
        >>> search_site("192.168.0.1")
        'SiteA'
    """

    ip = ipaddress.IPv4Address(ip)
    ip_network = ipaddress.IPv4Network(ip).supernet(new_prefix=search_network_prefix)

    sites = {
        device["siteName"]
        for device in all_devices
        if ipaddress.IPv4Address(device["loginIp"]) in ip_network
    }

    if catch_all_str in sites:
        sites.remove(catch_all_str)
    if len(sites) == 1:
        return sites.pop()
    if len(sites) > 1:
        all_potential_sites = f"{prefix_fixme}{'_'.join(sites)}"
        if len(all_potential_sites) > multi_site_str_limit:
            return f"{all_potential_sites[:multi_site_str_limit - 3]}..."
        return all_potential_sites

    return f"{prefix_fixme}no_site_found"


def search_subnet(ip: str, subnet_data: str) -> str:
    """
    Returns the site name based on the subnet from the subnet_data.

    Args:
        ip: The IP address to search for.
        subnet_data: The subnet data to search for.

    Returns:
        The name of the site associated with the IP address.

    Examples:
        >>> search_site("192.168.0.1")
        'SiteA'
    """

    ip = ipaddress.IPv4Address(ip)
    return next(
        (
            subnet["name"]
            for subnet in subnet_data
            if ip in ipaddress.IPv4Network(subnet["subnet"])
        ),
        None,
    )


def match_ipf_with_snow(ipf_devices, snow_devices):
    """
    Matches IPF devices with their corresponding devices in ServiceNow based on hostname.

    Args:
        snow_devices: A list of dictionaries representing devices in ServiceNow, each containing the following information:
            - name: The name of the device.
            - snow_location: The location of the device in ServiceNow.
        ipf_devices: A list of dictionaries representing IPF devices, each containing the following information:
            - hostname: The hostname of the device.

    Returns:
        A tuple containing two lists:
            - matched_devices: A list of dictionaries representing the matched devices, each containing the following information:
                - hostname: The hostname of the device.
                - snow_location: The location of the device in ServiceNow.
            - not_found_devices: A list of dictionaries representing the devices that could not be matched.
    """

    matched_devices = []
    not_found_devices = []

    for device in ipf_devices:
        match_hostname = False
        # check for exact hostname match
        for snow_device in snow_devices:
            if device["hostname"] == snow_device["name"]:
                device["snow_location"] = snow_device["snow_location"]
                matched_devices.append(device)
                match_hostname = True
                break

        # check for partial hostname match
        if not match_hostname:
            for snow_device in snow_devices:
                if (
                    snow_device["name"] in device["hostname"]
                    or device["hostname"] in snow_device["name"]
                ):
                    device["snow_location"] = snow_device["snow_location"]
                    matched_devices.append(device)
                    match_hostname = True
                    break

        if not match_hostname:
            not_found_devices.append(device)

    return matched_devices, not_found_devices


def validate_subnet_data(subnet_data: json) -> bool:
    """
    Validates the subnet data provided.

    Args:
        subnet_data: The subnet data to validate.

    Returns:
        True if the subnet data is valid, False otherwise.
    """
    if not subnet_data:
        logger.error("No subnet data provided")
        return False
    for subnet in subnet_data:
        try:
            ipaddress.IPv4Network(subnet["subnet"])
        except Exception as e:
            logger.error(f"Invalid subnet `{subnet['subnet']}`. Error: {e}")
            return False
    return True


def file_to_json(input: typer.FileText) -> json:
    try:
        output = json.load(input)
    except Exception as e:
        logger.error(f"Error loading file `{input}`, not a valid json. Error: {e}")
        sys.exit()
    return output


def export_to_csv(list, filename, output_folder) -> bool:
    """
    Exports a list of dictionaries to a CSV file using pandas, logs a message using the logger, and returns the resulting DataFrame.

    Args:
        list: A list of dictionaries to be exported.
        filename: The name of the CSV file to be created.
        output_folder: Location where the file will be saved.

    Returns:
        Boolean indicating if the file was saved successfully.
    """
    if not list:
        logger.warning(f"No data to export in the file `{filename}`")
        return False
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    output_file = f"{output_folder}/{filename}"
    try:
        result = pd.DataFrame(list)
        result.to_csv(output_file, index=False)
        logger.info(f"File `{output_file}` saved")
        return True
    except Exception as e:
        logger.error(f"Error saving file `{output_file}`. Error: {e}")
        return False


def export_to_excel(list, filename, output_folder) -> bool:
    """
    Exports a list of dictionaries to a CSV file using pandas, logs a message using the logger, and returns the resulting DataFrame.

    Args:
        list: A list of dictionaries to be exported.
        filename: The name of the CSV file to be created.
        output_folder: Location where the file will be saved.

    Returns:
        Boolean indicating if the file was saved successfully.
    """

    if not list:
        logger.warning("No data to export")
        return False
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    output_file = f"{output_folder}/{filename}"
    # # Filter the items in the list based on the COLUMNS
    # matched_columns = [key for key in list[0].keys() if key in REPORT_COLUMNS]

    # # Reorder the filtered list based on the order in the keys list
    # matched_columns_ordered = [key for key in REPORT_COLUMNS if key in matched_columns]
    # print(matched_columns)
    # print(matched_columns_ordered)
    try:
        result = pd.DataFrame(list, columns=REPORT_COLUMNS)
        result = result.dropna(axis=1, how='all')
        result.to_excel(output_file, index=False)
        logger.info(f"File `{output_file}` saved")
        return True
    except Exception as e:
        logger.error(f"Error saving file `{output_file}`. Error: {e}")
        return False


def read_site_sep_file(filename) -> Union[dict, bool]:
    """
    Reads a CSV file using pandas and returns the resulting DataFrame.

    Args:
        filename: The name of the CSV file to be read.

    Returns:
        A pandas DataFrame representing the data in the CSV file.
    """
    try:
        if filename.name.endswith(".csv"):
            df = pd.read_csv(filename.name)
            df.replace({np.nan: None}, inplace=True)
        elif filename.name.endswith(".xlsx"):
            df = pd.read_excel(filename.name)
            df.replace({np.nan: None}, inplace=True)
        else:
            logger.error(
                f"Invalid file format for file `{filename.name}`. Please provide a CSV or Excel file."
            )
            sys.exit()
    except Exception as e:
        logger.error(f"Error reading file `{filename}`. Error: {e}")
        sys.exit()
    try:
        result = df.to_dict(orient="records")
        logger.info(f"File `{filename.name}` loaded")
        return result
    except Exception as e:
        logger.error(f"Error transforming file `{filename}` to dict. Error: {e}")
        sys.exit()
