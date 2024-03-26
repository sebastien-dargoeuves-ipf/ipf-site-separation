import ipaddress
import json

import pandas as pd
import typer
from ipfabric import IPFClient
from ipfabric.settings import Attributes
from loguru import logger
from tqdm import tqdm

from modules.classDefinitions import Settings


def search_subnet(
    ip: str,
    subnet_data: str
) -> str:
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
        "no_subnet_match",
    )


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
        ipf_attributes = Attributes(client=ipf_client, snapshot_id=settings.IPF_SNAPSHOT_ID)
        request_update_attributes = ipf_attributes.set_sites_by_sn(attributes_list)
        ipf_attributes.set_sites_by_sn(attributes_list)
        logger.info(
            f"Local Attributes 'siteName' has been updated for {len(request_update_attributes)} devices"
        )

    return True


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
    """
    Processes devices with IP addresses by searching for their corresponding subnet based on the provided subnet data.
    If update_ipf is False, the devices' information is exported to a CSV file. Otherwise, the attributes of the devices are updated in IPF.

    Args:
        settings (Settings): The settings object containing configuration parameters.
        subnet_data (json): The subnet data used for subnet searching.
        update_ipf (bool): A flag indicating whether to update IPF or export to CSV.

    Returns:
        bool: True if the function completes successfully, False otherwise.
    """

    if not validate_subnet_data(subnet_data):
        return False

    ipf_client = initiate_ipf(settings)
    devices_with_ip = ipf_client.inventory.devices.all(
        filters={"loginIp": ["empty", False]},
        columns=["hostname", "loginIp", "sn", "model", "siteName"],
    )

    progress_bar = tqdm(total=len(devices_with_ip), desc="Processing Devices")
    for device in devices_with_ip:
        device["siteName"] = search_subnet(
            device["loginIp"],
            subnet_data
        )
        progress_bar.update(1)
    progress_bar.close()
    if not update_ipf:
        export_to_csv(devices_with_ip, settings.SUBNET_SITESEP_FILENAME)
    else:
        update_attributes(ipf_client, devices_with_ip, settings)
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
