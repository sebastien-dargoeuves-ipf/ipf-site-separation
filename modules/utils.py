import ipaddress
import json
import os
import sys
from typing import Union

import pandas as pd
import typer
from loguru import logger

MSG_NO_LOGINIP = "no loginIp"
MSG_SUBNET_NOT_FOUND = "subnet not found"


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


def match_ipf_with_snow(snow_devices, ipf_devices):
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


def create_site_sep_report(ipf_devices: list, managed_ip_addresses: list) -> list:
    """
    Builds a Site Separation report based on the list of devices and their managed IP

    Args:
        ipf_devices: A list of dictionaries representing the IP Fabric devices,
        managed_ip_addresses: A list of dictionaries representing the managed IP addresses,
        file_output: Location where the file will be saved.

    Returns:
        Return a list of dictionnary containing the report information for each device.
    """

    def find_mgmt_subnet(ipf_devices, managed_ip_addresses):
        """
        Finds the management subnet for each device based on the provided IPF devices and managed IP addresses.

        Args:
            ipf_devices: A list of dictionaries representing IPF devices.
            managed_ip_addresses: A list of dictionaries representing managed IP addresses.

        Returns:
            A list of dictionaries representing IPF devices with the management subnet information added.
        """
        # Convert Managed IP table to dict with devices as keys and IP addresses to IP objects
        logger.debug(
            "Converting Managed IP table to dict with devices as keys and IP addresses to IP objects"
        )
        mip_dict = {}
        for mip in managed_ip_addresses:
            mip["net"] = (
                ipaddress.IPv4Network(mip["net"], strict=True) if mip["net"] else None
            )
            if mip["hostname"] in mip_dict:
                mip_dict[mip["hostname"]].append(mip)
            else:
                mip_dict[mip["hostname"]] = [mip]
        logger.debug("Converting IP addresses in Device Inventory to IP objects")
        for device in ipf_devices:
            device["loginIp"] = (
                ipaddress.IPv4Address(device["loginIp"]) if device["loginIp"] else None
            )

        # Find the management subnet for each device
        logger.debug(
            "Finding the management subnet for each device, using loginIp and Managed IP table"
        )
        for device in ipf_devices:
            if not device["loginIp"]:
                device["net"] = MSG_NO_LOGINIP
                continue
            mips = mip_dict.get(device["hostname"], [])
            for mip in mips:
                if mip["net"] and device["loginIp"] in mip["net"]:
                    device["net"] = mip["net"]
                    break
            else:
                device["net"] = MSG_SUBNET_NOT_FOUND

        return ipf_devices

    def create_subnet_site_report(devices_report):
        """
        Creates a subnet site report based on the provided report data.

        Args:
            report: A list of dictionaries representing site entries.

        Returns:
            A dictionary containing the subnet site report with entry statistics.
        """
        from collections import defaultdict

        site_entry_count = defaultdict(lambda: defaultdict(int))

        # Count the number of devices for each site in each subnet
        logger.debug("Counting the number of devices for each site in each subnet")
        for entry in devices_report:
            site_name = entry["siteName"]
            if entry["net"] in [MSG_NO_LOGINIP, MSG_SUBNET_NOT_FOUND]:
                continue
            net = entry["net"]
            site_entry_count[net][site_name] += 1

        subnet_report = {}
        logger.debug("Calculating the entry statistics for each subnet")
        for subnet, sites in site_entry_count.items():
            entry_stats = {
                net: {
                    "count": count,
                    "percent": float(f"{count / sum(sites.values()) * 100:.2f}"),
                }
                for net, count in sites.items()
            }
            subnet_report[subnet] = entry_stats

        return subnet_report

    def suggested_final_site(matching_sites):
        """
        Returns the suggested final site based on the matching sites.

        Args:
            matching_sites: A dictionary containing the matching sites for a subnet.

        Returns:
            The suggested final site.
        """
        if matching_sites:
            suggested_site = next(
                (
                    site
                    for site, data in matching_sites.items()
                    if data["percent"] >= 50
                ),
                "",
            )
            return suggested_site
        return ""

    # Find the management subnet for each device
    logger.info("Finding the management subnet for each device...")
    devices_report = find_mgmt_subnet(ipf_devices, managed_ip_addresses)
    # Create the table containing all sites for each management subnet
    subnet_site_report = create_subnet_site_report(devices_report)
    logger.info("... and putting the data together")
    for device in devices_report:
        device["matchingSites"] = subnet_site_report.get(device["net"])
        device["suggestedFinalSite"] = suggested_final_site(device["matchingSites"])
        device["suggested eq IPF Site"] = (
            device["suggestedFinalSite"] == device["siteName"]
        )
        device["finalSite"] = ""

    return devices_report


def file_to_json(input: typer.FileText) -> json:
    try:
        output = json.load(input)
    except Exception as e:
        logger.error(f"Error loading file `{input}`, not a valid json. Error: {e}")
        sys.exit("Invalid file")
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
        logger.warning("No data to export")
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
    try:
        result = pd.DataFrame(list)
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
            df = pd.read_csv(filename)
        elif filename.name.endswith(".xlsx"):
            df = pd.read_excel(filename)
        else:
            logger.error(
                f"Invalid file format for file `{filename.name}`. Please provide a CSV or Excel file."
            )
            return False
    except Exception as e:
        logger.error(f"Error reading file `{filename}`. Error: {e}")
        return False
    try:
        result = df.to_dict(orient="records")
        logger.info(f"File `{filename.name}` loaded")
        return result
    except Exception as e:
        logger.error(f"Error transforming file `{filename}` to dict. Error: {e}")
        return False