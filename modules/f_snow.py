"""
ServiceNow Functions
"""

from loguru import logger

from modules.utils import export_to_csv, match_ipf_with_snow
from modules.f_ipf import initiate_ipf, update_attributes
from modules.classDefinitions import Settings

from ipfabric_snow.utils.servicenow_client import Snow
from modules.classDefinitions import Settings


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
        export_to_csv(
            matched_devices, settings.IPF_SNOW_MATCHED_FILENAME, settings.OUTPUT_FOLDER
        )
        export_to_csv(
            not_found_devices,
            settings.IPF_SNOW_NOT_MATCHED_FILENAME,
            settings.OUTPUT_FOLDER,
        )
    else:
        update_attributes(ipf_client, matched_devices, settings)

    return True
