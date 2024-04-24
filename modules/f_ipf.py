"""
IP Fabric functions
"""

import json

import typer
from ipfabric import IPFClient
from ipfabric.settings import Attributes
from loguru import logger
from tqdm import tqdm

from modules.settings import Settings
from modules.utils import (
    create_site_sep_report,
    export_to_csv,
    export_to_excel,
    file_to_json,
    read_site_sep_file,
    search_site,
    search_subnet,
    validate_subnet_data,
)

try:
    from yaspin import yaspin

    YASPIN_ANIMATION = True
except ImportError:
    YASPIN_ANIMATION = False

# from ipdb import set_trace as debug


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


def update_attributes(
    ipf_client: IPFClient,
    devices: list,
    settings: Settings,
    attributes_list: list = None,
):
    """
    Updates attributes in IPF based on the devices provided.

    Args:
        ipf_client: An instance of IPFClient used to update the attributes.
        devices: A list of dictionaries representing the devices, each containing, at minima, the following information:
            - sn: The serial number of the device.
            - key:value of the attributes to create/update.
        settings: An instance of the Settings class containing the IP Fabric settings.
        attributes_list: A list of attributes to update.


    Returns:
        False if no devices are provided, otherwise True.
    """

    if attributes_list is None:
        attributes_list = ["siteName"]
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

    # build the list of attributes mapping
    attributes_mapping = []
    for attribute in attributes_list:
        if devices[0].get(attribute, "not_valid_attribute") != "not_valid_attribute":
            attributes_mapping += [
                {"sn": d["sn"], "name": attribute, "value": d.get(attribute)}
                for d in devices
                if d.get(attribute)
            ]
        else:
            logger.warning(
                f"Attribute {attribute} is not present in the file provided."
            )
            typer.confirm(
                "Do you want to continue with the other attributes?",
                default=False,
                abort=True,
            )
            attributes_list.remove(attribute)

    if not attributes_mapping:
        logger.error("No attributes to update")
        return False

    if update_global_attributes:
        ipf_attributes = Attributes(client=ipf_client)
        request_update_attributes = ipf_attributes.set_attributes_by_sn(
            attributes_mapping
        )
        logger.info(
            f"Global Attributes '{attributes_list}' updated! ({len(request_update_attributes)} entries)"
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
        request_update_attributes = ipf_attributes.set_attributes_by_sn(
            attributes_mapping
        )
        logger.info(
            f"Local Attributes '{attributes_list}' {'cleared and created!' if clear_local else 'updated!'} ({len(request_update_attributes)} entries)"
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
            list=catch_all_devices,
            filename=settings.CATCH_ALL_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
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
            list=site_separation_devices,
            filename=settings.SUBNET_SITESEP_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
        )
    else:
        update_attributes(ipf_client, site_separation_devices, settings)
    return True


def f_push_attribute_from_file(
    settings: Settings,
    site_separation_file: json,
    update_ipf: bool,
    attributes_list: list = None,
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
            list=site_separation_json,
            filename=settings.IMPORT_SITESEP_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
        )
    return update_attributes(
        ipf_client, site_separation_json, settings, attributes_list
    )


def f_ipf_report_site_sep(settings: Settings, file_output: str):
    """
    Publish a report containing info regarding site separation.
    | device  | sn  | loginIP | Subnet (based on loginIP & mask) | ipf Site | sites matching the subnet       | suggestedFinalSite | FinalSite |
    | ------- | --- | ------- | -------------------------------- | -------- | ------------------------------- | ------------------ | --------- |
    | deviceA | snA | 1.1.1.1 | 1.1.1.0/26                       | site1    | [site1: 30, site2:50, site3:20] | site2              |           |

    Args:
        settings: An object containing the settings for the operation.
        output: the CSV file where to save the report.
    """

    if not file_output.endswith(".xlsx"):
        file_output += ".xlsx"

    # Initialize IP Fabric client
    ipf_client = initiate_ipf(settings)

    # Collecting Device inventory
    logger.info("Collecting Device inventory...")
    if YASPIN_ANIMATION:
        spinner = yaspin(
            text="Collecting Device inventory",
            color="yellow",
            timer=True,
        )
        spinner.start()

    ipf_devices = ipf_client.inventory.devices.all(
        columns=["hostname", "loginIp", "sn", "siteName"],
    )
    if YASPIN_ANIMATION:
        spinner.ok("✅ ")

    # Collecting Managed IP table
    logger.info("Collecting Managed IP table...")
    if YASPIN_ANIMATION:
        spinner = yaspin(
            text="Collecting Managed IP table",
            color="yellow",
            timer=True,
        )
        spinner.start()
    managed_ip_addresses = ipf_client.technology.addressing.managed_ip_ipv4.all()
    if YASPIN_ANIMATION:
        spinner.ok("✅ ")

    # Generate report
    logger.info("Data collected, ready to start generating the report.")
    devices_report = create_site_sep_report(ipf_devices, managed_ip_addresses)

    return export_to_excel(devices_report, file_output, settings.REPORT_FOLDER)
