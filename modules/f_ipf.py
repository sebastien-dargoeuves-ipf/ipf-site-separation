"""
IP Fabric functions
"""

import io
import json
import os
import sys
import time

import typer
from ipfabric import IPFClient
from ipfabric.settings import Attributes
from loguru import logger
from modules.f_report import create_site_sep_report
from modules.settings import Settings
from modules.utils import (
    export_to_csv,
    export_to_excel,
    file_to_json,
    read_site_sep_file,
    search_site,
    search_subnet,
    validate_subnet_data,
)
from packaging import version
from rich.console import Console
from rich.progress import track

ATTRIBUTES_UPDATE_MAX = 10000

console = Console()


def run_with_spinner(task_name: str, task_func, *args, **kwargs):
    """
    Run a task with a spinner.

    Args:
        task_name: The name of the task.
        task_func: The function to run.
        *args: The arguments to pass to the function.
        **kwargs: The keyword arguments to pass to the function.

    Returns:
        The result of the task function.
    """
    logger.info(f"{task_name}...")
    start_time = time.time()
    with console.status(f"[bold yellow] {task_name}..."):
        result = task_func(*args, **kwargs)
    elapsed_time = time.time() - start_time
    console.log(f"completed in {elapsed_time:.2f} seconds")
    logger.info(f"✅ {task_name} completed in {elapsed_time:.2f} seconds")
    return result


def initiate_ipf(settings: Settings):
    """
    Initializes an IPFClient instance with the provided settings.

    Args:
        settings: An instance of the Settings class containing the IP Fabric settings.

    Returns:
        An instance of IPFClient.
    """
    import logging

    logging.getLogger("ipfabric").setLevel(logging.INFO)
    return IPFClient(
        base_url=settings.IPF_URL,
        auth=settings.IPF_TOKEN,
        snapshot_id=settings.IPF_SNAPSHOT_ID,
        timeout=settings.IPF_TIMEOUT,
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
        update_only: Bool to define if we are taking all entries from the file, or only the ones to update


    Returns:
        False if no devices are provided, otherwise True.
    """

    def set_attr_by_sn(ipf_client, ipf_attributes, attributes_mapping):
        """
        Set IP Fabric attributes by serial number.

        Args:
            ipf_attributes: IP Fabric attributes object.
            attributes_mapping: Mapping of attributes to set.

        Returns:
            Request update attributes if successful, False otherwise.
        Raises:
            Exception: If setting attributes fails after retrying.

        Examples:
            set_attr_by_sn(ipf_client, ipf_attributes, attributes_mapping)
        """
        try:
            request_update_attributes = ipf_attributes.set_attributes_by_sn(attributes_mapping)
        except Exception as e:
            if 0 < ipf_client.timeout.read < 30:
                ipf_client.timeout = 5 * ipf_client.timeout.read
            else:
                ipf_client.timeout = 2 * ipf_client.timeout.read
            logger.warning(f"IP Fabric API Issue: {e}\nRetrying with a timeout of {ipf_client.timeout}s...")
            ipf_attributes = Attributes(client=ipf_client, snapshot_id=ipf_client.snapshot_id)
            try:
                request_update_attributes = ipf_attributes.set_attributes_by_sn(attributes_mapping)
            except Exception as e:
                logger.error(f"2nd attempt failed: {e}")
                if "400 Bad Request" in e.args[0]:
                    logger.info(
                        f"This could be due to the size of the 'attributes_mapping': {sys.getsizeof(attributes_mapping)} bytes.\nTry to reduce the number of attributes to push (roughly <125000 bytes)"
                    )
                sys.exit(1)

        return request_update_attributes

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
            f"(Optional) Do you want to update local attributes? It will recalculate siteSeparation for snapshot `{settings.IPF_SNAPSHOT_ID}`",
            default=not update_global_attributes,
        )
    )

    # build the list of attributes mapping
    attributes_mapping = []
    for attribute in attributes_list:
        if devices[0].get(attribute, "not_valid_attribute") != "not_valid_attribute":
            attributes_mapping += [
                {"sn": d["sn"], "name": attribute, "value": d.get(attribute)} for d in devices if d.get(attribute)
            ]
        else:
            logger.warning(f"Attribute {attribute} is not present in the file provided.")
            typer.confirm(
                "Do you want to continue with the other attributes?",
                default=False,
                abort=True,
            )
            attributes_list.remove(attribute)

    if not attributes_mapping:
        logger.error("No attributes to update")
        return False

    split_attributes_mapping = [
        attributes_mapping[i : i + ATTRIBUTES_UPDATE_MAX]
        for i in range(0, len(attributes_mapping), ATTRIBUTES_UPDATE_MAX)
    ]

    if update_global_attributes:
        ipf_attributes = Attributes(client=ipf_client)
        clear_global = False
        if all_attributes := ipf_attributes.all():
            if clear_global := typer.confirm(
                "Do you want to clear the existing global attributes?\n /!\ YOU WILL LOSE ALL PREVIOUSLY ADDED ATTRIBUTES /!\\",
                default=False,
            ):
                try:
                    ipf_attributes.delete_attribute(*all_attributes)
                    logger.debug("Global attributes cleared")
                except Exception as e:
                    logger.error(f"Failed to clear Global attributes: {e}")
                    sys.exit(1)

        for index, attributes_batch in enumerate(split_attributes_mapping):
            request_update_attributes = set_attr_by_sn(ipf_client, ipf_attributes, attributes_batch)
            if len(split_attributes_mapping) > 1:
                logger.info(
                    f"Updating... part {index+1}/{len(split_attributes_mapping)}: {len(request_update_attributes)} entries ({len(request_update_attributes)/len(attributes_mapping)*100:.2f}%)"
                )
        logger.info(
            f"Global Attributes '{attributes_list}' {'cleared and created!' if clear_global else 'updated!'} ({len(attributes_mapping)} entries)"
        )

    if update_local_attributes:
        ipf_client.snapshot_id = settings.IPF_SNAPSHOT_ID
        ipf_attributes = Attributes(client=ipf_client, snapshot_id=settings.IPF_SNAPSHOT_ID)
        clear_local = False
        if all_attributes := ipf_attributes.all():
            if clear_local := typer.confirm(
                "Do you want to clear local attributes beforehand? If not it will only update the matching entries.",
                default=False,
            ):
                try:
                    ipf_attributes.delete_attribute(*all_attributes)
                    logger.debug("Local attributes cleared")
                except Exception as e:
                    logger.error(f"Failed to clear local attributes: {e}")
                    sys.exit(1)

        if len(split_attributes_mapping) > 1 and not typer.confirm(
            f"\nUpdating local attribute when you have more than {ATTRIBUTES_UPDATE_MAX} entries is NOT supported, as the recalculation will happens more than once during the execution of the script.\n\nDo you wish to continue?",
            default=False,
        ):
            logger.warning(
                f"Exit due to lack of support of updating local attribute with more than {ATTRIBUTES_UPDATE_MAX} entries"
            )
            sys.exit(0)
        for index, attributes_batch in enumerate(split_attributes_mapping):
            request_update_attributes = set_attr_by_sn(ipf_client, ipf_attributes, attributes_batch)
            # display the progress based on the number of entries and the index
            if len(split_attributes_mapping) > 1:
                logger.info(
                    f"Updating... part {index+1}/{len(split_attributes_mapping)}: {len(request_update_attributes)} entries ({len(request_update_attributes)/len(attributes_mapping)*100:.2f}%)"
                )
        logger.info(
            f"Local Attributes '{attributes_list}' {'cleared and created!' if clear_local else 'updated!'} ({len(attributes_mapping)} entries)"
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

    for device in track(catch_all_devices, description="CatchAll - Processing Devices"):
        device["siteName"] = search_site(
            device["loginIp"],
            all_devices,
            settings.CATCH_ALL,
            settings.SEARCH_NETWORK_PREFIX,
            settings.MULTI_SITE_LIMIT,
            settings.PREFIX_FIXME,
        )

    if not update_ipf:
        export_to_csv(
            list=catch_all_devices,
            filename=settings.CATCH_ALL_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
        )
    else:
        update_attributes(ipf_client=ipf_client, devices=catch_all_devices, settings=settings)
    return True


def f_ipf_subnet(settings: Settings, subnet_file: io.TextIOWrapper, attribute_to_update: str, update_ipf: bool):
    subnet_data = file_to_json(subnet_file)
    if not validate_subnet_data(subnet_data):
        return False

    ipf_client = initiate_ipf(settings)
    devices_with_ip = ipf_client.inventory.devices.all(
        filters={"loginIp": ["empty", False]},
        columns=["hostname", "loginIp", "sn", "model", "siteName"],
    )
    new_attributes_devices = []

    for device in track(devices_with_ip, description="Subnet - Processing Devices"):
        if new_site := search_subnet(device["loginIp"], subnet_data):
            new_attributes_devices.append(
                {
                    "sn": device["sn"],
                    attribute_to_update: new_site,
                }
            )

    if not update_ipf:
        export_to_csv(
            list=new_attributes_devices,
            filename=settings.SUBNET_SITESEP_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
        )
    else:
        update_attributes(
            ipf_client=ipf_client,
            devices=new_attributes_devices,
            settings=settings,
            attributes_list=[attribute_to_update],
        )
    return True


def f_push_attribute_from_file(
    settings: Settings,
    site_separation_file: json,
    update_only: bool,
    dry_run: bool,
    attributes_list: list = None,
):
    """
    Pushes attributes from a site separation file to IPF.

    Args:
        settings: An object containing the settings for the operation.
        site_separation_file: A CSV or XLSX file containing site separation data.
        dry_run: A boolean indicating whether to update IPF or export to CSV.
    """

    site_separation_json = read_site_sep_file(site_separation_file, update_only)
    ipf_client = initiate_ipf(settings)
    if dry_run:
        return export_to_csv(
            list=site_separation_json,
            filename=settings.IMPORT_SITESEP_FILENAME,
            output_folder=settings.OUTPUT_FOLDER,
        )
    return update_attributes(
        ipf_client=ipf_client,
        devices=site_separation_json,
        settings=settings,
        attributes_list=attributes_list,
    )


def f_ipf_report_site_sep(
    settings: Settings,
    file_output: str,
    hostname_match: bool,
    connectivity_matrix_match: bool,
    recheck_site_sep: bool,
):  # sourcery skip: extract-duplicate-method, extract-method
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
    ipf_devices = run_with_spinner(
        "Collecting Device inventory",
        ipf_client.inventory.devices.all,
        columns=["hostname", "loginIp", "sn", "siteName"],
    )

    # Collecting Managed IP table
    managed_ip_addresses = run_with_spinner(
        "Collecting Managed IP table",
        ipf_client.technology.addressing.managed_ip_ipv4.all,
    )

    connectivity_matrix = None
    if connectivity_matrix_match:
        # Collecting Connectivity Matrix
        connectivity_matrix = run_with_spinner(
            "Collecting Connectivity Matrix table",
            ipf_client.technology.interfaces.connectivity_matrix.all,
            filters={"protocol": ["neq", "cef"]},
        )
    # Generate report
    logger.info("Data collected, ready to start generating the report.")
    devices_report = create_site_sep_report(
        settings=settings,
        ipf_devices=ipf_devices,
        managed_ip_addresses=managed_ip_addresses,
        hostname_match=hostname_match,
        connectivity_matrix_match=connectivity_matrix_match,
        connectivity_matrix=connectivity_matrix,
        recheck_site_sep=None,
    )
    if recheck_site_sep:
        logger.info("Re-processing the data, using the calculated data...")
        devices_report = create_site_sep_report(
            settings=settings,
            ipf_devices=None,
            managed_ip_addresses=None,
            hostname_match=hostname_match,
            connectivity_matrix_match=connectivity_matrix_match,
            connectivity_matrix=connectivity_matrix,
            recheck_site_sep=devices_report,
        )

    return export_to_excel(devices_report, file_output, settings.REPORT_FOLDER)


def f_ipf_rules_collect(
    settings: Settings,
    file_str: str
):
    # Check if the file already exists
    if os.path.exists("/".join([settings.OUTPUT_FOLDER,file_str])):
        # Prompt user about overwriting
        overwrite = typer.confirm(f"The file {file_str} already exists. Do you want to overwrite it?")

        if not overwrite:
            # Exit or choose an alternative filename
            typer.echo("Operation cancelled.")
            raise typer.Abort()
    # Initialize IP Fabric client
    ipf_client = initiate_ipf(settings)
    # Collecting Site Separation rules
    if site_separation_rules := ipf_client.settings.site_separation.get_separation_rules().get(
        'rules', []
    ):
        export_to_csv(
            list=site_separation_rules,
            filename=file_str,
            output_folder=settings.OUTPUT_FOLDER,
        )
        logger.info(f"{len(site_separation_rules)} site separation rules collected.")
        return True
    else:
        logger.warning("No site separation rules found.")
        return False
    

def f_ipf_rules_update(
    settings: Settings,
    file_str: str
):
    # Nothing to import if the file does not exist
    if not os.path.exists(file_str):
        logger.error(f"The file {file_str} does not exist.")
        raise typer.Exit(code=1)

    new_rules_json = file_to_json(file_str)

    ipf_client = initiate_ipf(settings)

    # Check if the version is below 7.0.0
    is_pre_7_version = version.parse(ipf_client.os_version) < version.parse("7.0.0")
    logger.info("SiteSeparation rules `regexCloudResourceId` are not supported in versions below 7.0.0")
    logger.info("Checking and updating the rules...")
    # Filter and modify rules
    filtered_rules = []
    for rule in new_rules_json:
        # Remove regexCloudResourceId rules for versions below 7.0.0
        if rule.get('type') == 'regexCloudResourceId' and is_pre_7_version:
            continue
        # Remove applyToCloudInstances key/value for regexHostname rules
        if rule.get('type') == 'regexHostname':
            rule.pop("applyToCloudInstances", None)
        filtered_rules.append(rule)

    rules_settings = ipf_client.settings.site_separation.get_separation_rules()
    logger.info(f"{len(rules_settings['rules'])} existing rules will be removed and replaced by the {len(new_rules_json)} new rules from {ipf_client.base_url}")
    if typer.confirm(
        "Do you want to continue?",
        default=True,
    ):
        rules_settings["rules"] = new_rules_json
        patch_request = ipf_client.patch(url="/settings",json={"siteSeparation": rules_settings})
        if patch_request.status_code == 200:
            logger.success(f"The rules from the file {file_str} are now applied to {ipf_client.base_url}")
        else:
            logger.warning(f"Failed to update the rules: {patch_request.text}")
            return False
        return True
    else:
        logger.info("Update cancelled by user.")
        raise typer.Abort()

