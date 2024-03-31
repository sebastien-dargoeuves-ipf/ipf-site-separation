"""
IP Fabric functions
"""

import json
import typer
from loguru import logger
from ipfabric import IPFClient
from tqdm import tqdm
from ipfabric.settings import Attributes

from modules.utils import (
    search_site,
    search_subnet,
    export_to_csv,
    validate_subnet_data,
    file_to_json,
    read_site_sep_file,
    create_site_sep_report,
)
from modules.classDefinitions import Settings


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
        False if no devices are provided, otherwise True.
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
        clear_local = False
        if all_attributes := ipf_attributes.all():
            if clear_local := typer.confirm(
                "Do you want to clear local attributes beforehand? If not it will only update the matching entries.",
                default=True,
            ):
                ipf_attributes.delete_attribute(*all_attributes)
        request_update_attributes = ipf_attributes.set_sites_by_sn(attributes_list)
        logger.info(
            f"Local Attributes 'siteName' has been {'cleared and created' if clear_local else 'updated'} for {len(request_update_attributes)} devices"
        )

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
        export_to_csv(
            catch_all_devices, settings.CATCH_ALL_FILENAME, settings.OUTPUT_FOLDER
        )
    else:
        update_attributes(ipf_client, catch_all_devices, settings)
    return True


def f_ipf_subnet(settings: Settings, subnet_file: json, update_ipf: bool):

    subnet_data = file_to_json(subnet_file)
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
        export_to_csv(
            site_separation_devices,
            settings.SUBNET_SITESEP_FILENAME,
            settings.OUTPUT_FOLDER,
        )
    else:
        update_attributes(ipf_client, site_separation_devices, settings)
    return True


def f_push_attribute_from_file(
    settings: Settings, site_separation_file: json, update_ipf: bool
):
    """
    Pushes attributes from a site separation file to IPF.

    Args:
        settings: An object containing the settings for the operation.
        site_separation_file: A CSV or XLSX file containing site separation data.
        update_ipf: A boolean indicating whether to update IPF or export to CSV.
    """

    site_separation_json = read_site_sep_file(site_separation_file)
    ipf_client = initiate_ipf(settings)
    if not update_ipf:
        return export_to_csv(
            site_separation_json,
            settings.IMPORT_SITESEP_FILENAME,
            settings.OUTPUT_FOLDER,
        )
    else:
        return update_attributes(ipf_client, site_separation_json, settings)


def f_ipf_report_site_sep(settings: Settings, output_file: str):
    """
    Publish a report containing info regarding site separation.
    | device  | sn  | loginIP | Subnet (based on loginIP & mask) | ipf Site | sites matching the subnet       | suggestedFinalSite | FinalSite |
    | ------- | --- | ------- | -------------------------------- | -------- | ------------------------------- | ------------------ | --------- |
    | deviceA | snA | 1.1.1.1 | 1.1.1.0/26                       | site1    | [site1: 30, site2:50, site3:20] | site2              |           |

    Args:
        settings: An object containing the settings for the operation.
        output: the CSV file where to save the report.
    """

    if not output_file.endswith(".csv"):
        output_file += ".csv"

    ipf_client = initiate_ipf(settings)
    ipf_devices = ipf_client.inventory.devices.all(
        columns=["hostname", "loginIp", "sn", "siteName"]
    )
    managed_ip_addresses = ipf_client.technology.addressing.managed_ip_ipv4.all()
    return create_site_sep_report(ipf_devices, managed_ip_addresses, output_file)
