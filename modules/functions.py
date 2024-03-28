import ipaddress
import json

import pandas as pd
import typer
from ipfabric import IPFClient
from ipfabric.settings import Attributes
from ipfabric_snow.utils.servicenow_client import Snow
from loguru import logger
from tqdm import tqdm

from modules.classDefinitions import Settings
from ipdb import set_trace as debug


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


def get_snow_device_list(snow_client):
    """
    Retrieves a list of devices from ServiceNow along with their associated information.

    Args:
        snow_client: An instance of the ServiceNow client.

    Returns:
        A list of dictionaries, each containing the following device information:
            - name: The name of the device.
            - ip_address: The IP address of the device.
            - serial_number: The serial number of the device.
            - snow_location: The location of the device in ServiceNow.
    """

    cmdb_table_devices = "cmdb_ci_netgear"
    full_snow_devices = snow_client.request_client.get_all_records(cmdb_table_devices)

    cmdb_table_locations = "cmn_location"
    full_snow_locations = snow_client.request_client.get_all_records(
        cmdb_table_locations
    )
    location_dict = {
        loc["sys_id"]: loc["name"] for loc in full_snow_locations["result"]
    }

    snow_devices = []
    for device in full_snow_devices["result"]:
        location_id = device["location"]["value"]
        location_name = location_dict.get(location_id)
        new_device = {
            "name": device["name"],
            "ip_address": device["ip_address"],
            "serial_number": device["serial_number"],
            "snow_location": location_name,
        }
        snow_devices.append(new_device)
    return snow_devices


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


def update_attributes(ipf_client: IPFClient, devices: list, settings: Settings):
    """
    Updates attributes in IPF based on the devices provided.

    Args:
        ipf: An instance of IPFClient used to update the attributes.
        devices: A list of dictionaries representing the devices, each containing the following information:
            - sn: The serial number of the device.
            - snow_location: The location of the device in ServiceNow.
            - siteName: The name of the site associated with the device.

    Returns:
        False if no devices are provided, otherwise None.
    """

    if not devices:
        logger.info("No device matching - no attribute to update")
        return False

    update_global_attributes = bool(
        typer.confirm(
            "(Recommended) Do you want to update global attributes?",
            default=True,
        )
    )
    update_local_attributes = bool(
        typer.confirm(
            f"(Optional) Do you want to update local attributes? It will recalculate siteSeparation for snapshot `{settings.IPF_SNAPSHOT_ID}`"
        )
    )
    attributes_list = [
        {"sn": d["sn"], "value": d.get("snow_location") or d.get("siteName")}
        for d in devices
    ]

    if update_global_attributes:
        ipf_attributes = Attributes(client=ipf_client)
        request_update_attributes = ipf_attributes.set_sites_by_sn(attributes_list)
        logger.info(
            f"Global Attributes 'siteName' has been updated for {len(request_update_attributes)} devices"
        )
    if update_local_attributes:
        ipf_attributes = Attributes(
            client=ipf_client, snapshot_id=settings.IPF_SNAPSHOT_ID
        )
        if all_attributes := ipf_attributes.all():
            if typer.confirm(
                "Do you want to clear local attributes beforehand? If not it will only update the matching entries.",
                default=True,
            ):
                ipf_attributes.delete_attribute(*all_attributes)
        request_update_attributes = ipf_attributes.set_sites_by_sn(attributes_list)
        logger.info(
            f"Local Attributes 'siteName' has been cleared and created for {len(request_update_attributes)} devices"
        )

    return True


def initiate_snow(settings: Settings):
    """
    Initializes a Snow instance with the provided settings.

    Args:
        settings: An instance of the Settings class containing the ServiceNow settings.

    Returns:
        An instance of Snow.
    """
    return Snow(
        auth=(settings.SNOW_USER, settings.SNOW_PASS),
        url=settings.SNOW_URL,
        httpx_timeout=settings.SNOW_TIMEOUT,
    )


def initiate_ipf(settings: Settings):
    """
    Initializes an IPFClient instance with the provided settings.

    Args:
        settings: An instance of the Settings class containing the IP Fabric settings.

    Returns:
        An instance of IPFClient.
    """
    return IPFClient(
        base_url=settings.IPF_URL,
        auth=settings.IPF_TOKEN,
        snapshot_id=settings.IPF_SNAPSHOT_ID,
    )


def f_snow_site_sep(settings: Settings, update_ipf: bool):
    """
    Performs the site separation process by matching devices between ServiceNow and IP Fabric,
    updating IP Fabric attributes if specified.

    Args:
        settings: An instance of the Settings class containing the configuration settings.
        update_ipf: A boolean indicating whether to update IP Fabric attributes or not.

    Returns:
        True if the process is completed successfully.
    """
    snow_client = initiate_snow(settings)
    snow_devices = get_snow_device_list(snow_client)

    ipf_client = initiate_ipf(settings)
    ipf_devices = ipf_client.inventory.devices.all(
        columns=["hostname", "loginIp", "sn", "siteName"]
    )

    matched_devices, not_found_devices = match_ipf_with_snow(snow_devices, ipf_devices)
    if not update_ipf:
        logger.info("Dry run mode enabled, no data will be pushed to IP Fabric")
        export_to_csv(matched_devices, settings.IPF_SNOW_MATCHED_FILENAME)
        export_to_csv(not_found_devices, settings.IPF_SNOW_NOT_MATCHED_FILENAME)
    else:
        update_attributes(ipf_client, matched_devices, settings)

    return True


def f_ipf_catch_all(settings: Settings, update_ipf: bool):

    ipf_client = initiate_ipf(settings)
    catch_all_devices = ipf_client.inventory.devices.all(
        filters={"siteName": ["eq", settings.CATCH_ALL]},
        columns=["hostname", "loginIp", "sn", "model"],
    )
    all_devices = ipf_client.inventory.devices.all(
        columns=["hostname", "loginIp", "sn", "model", "siteName"],
    )

    progress_bar = tqdm(total=len(catch_all_devices), desc="Processing Devices")
    for device in catch_all_devices:
        device["siteName"] = search_site(
            device["loginIp"],
            all_devices,
            settings.CATCH_ALL,
            settings.SEARCH_NETWORK_PREFIX,
            settings.MULTI_SITE_LIMIT,
            settings.PREFIX_FIXME,
        )
        progress_bar.update(1)
    progress_bar.close()
    if not update_ipf:
        export_to_csv(catch_all_devices, settings.CATCH_ALL_FILENAME)
    else:
        update_attributes(ipf_client, catch_all_devices, settings)
    return True


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


def f_ipf_subnet(settings: Settings, subnet_data: json, update_ipf: bool):

    if not validate_subnet_data(subnet_data):
        return False

    ipf_client = initiate_ipf(settings)
    devices_with_ip = ipf_client.inventory.devices.all(
        filters={"loginIp": ["empty", False]},
        columns=["hostname", "loginIp", "sn", "model", "siteName"],
    )
    site_separation_devices = []
    progress_bar = tqdm(total=len(devices_with_ip), desc="Processing Devices")
    for device in devices_with_ip:
        if new_site := search_subnet(device["loginIp"], subnet_data):
            site_separation_devices.append(
                {
                    "sn": device["sn"],
                    "siteName": new_site,
                }
            )
        progress_bar.update(1)
    progress_bar.close()
    if not update_ipf:
        export_to_csv(site_separation_devices, settings.SUBNET_SITESEP_FILENAME)
    else:
        update_attributes(ipf_client, site_separation_devices, settings)
    return True


def export_to_csv(list, filename):
    """
    Exports a list of dictionaries to a CSV file using pandas, logs a message using the logger, and returns the resulting DataFrame.

    Args:
        list: A list of dictionaries to be exported.
        filename: The name of the CSV file to be created.
        message: The message to be logged.

    Returns:
        A pandas DataFrame representing the exported data.
    """
    result = pd.DataFrame(list)
    result.to_csv(filename, index=False)
    logger.info(f"File `{filename}` saved")
    return result
