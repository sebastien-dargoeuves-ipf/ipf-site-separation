import os
from typing import List

import typer
from loguru import logger

from modules.f_ipf import (
    f_ipf_catch_all,
    f_ipf_report_site_sep,
    f_ipf_subnet,
    f_push_attribute_from_file,
)
from modules.f_snow import f_snow_site_sep
from modules.settings import Settings

settings = Settings()
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=True,
)


@app.callback()
def logging_configuration():
    """
    Configures logging settings for the script execution.

    Args:
        None

    Returns:
        None
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_dir = os.path.join(root_dir, "logs")
    os.makedirs(default_log_dir, exist_ok=True)
    log_file_path = os.path.join(default_log_dir, "log_file.log")
    logger.add(
        log_file_path,
        retention="180 days",
        rotation="1 MB",
        level="INFO",
        compression="tar.gz",
    )
    logger.info("---- NEW EXECUTION OF SCRIPT ----")


@app.command("snow", help="Build Site Separation using ServiceNow data.")
def snow(
    update_ipf: bool = typer.Option(
        False,
        help="Dry Mode is default, if this option is enabled, it will update IP Fabric Attributes",
    ),
):
    """
    Executes the site separation process by checking information from ServiceNow and updating IP Fabric attributes if specified.

    Args:
        update_ipf: A boolean indicating whether to update IP Fabric attributes or not.
    """
    if f_snow_site_sep(settings, update_ipf):
        logger.info("'snow' task completed")
    else:
        logger.warning("'snow' task failed")


@app.command(
    "catch_all",
    help="Cleanup the devices belonging to a `catch_all` site, specified in settings.py",
)
def catch_all_cleanup(
    update_ipf: bool = typer.Option(
        False,
        help="Dry Mode is default, if this option is enabled, it will update IP Fabric Attributes",
    ),
):
    """
    Cleans up devices with the _catch_all_ site in IP Fabric by updating their siteName attribute in IP Fabric.

    Args:
        update_ipf: A boolean indicating whether to update IP Fabric attributes or not.
    """
    if f_ipf_catch_all(settings, update_ipf):
        logger.info("'catch_all' task completed")
    else:
        logger.warning("'catch_all' task failed")


@app.command(
    "subnet", help="Build Site Separation based on Subnet data provided in a json file."
)
def subnet(
    subnet_source: typer.FileText = typer.Argument(
        ...,
        help="The file containing the subnet information: [{name: 'site1', subnet: '1.1.1.0/24'}, ...]",
    ),
    update_ipf: bool = typer.Option(
        False,
        help="Dry Mode is default, if this option is enabled, it will update IP Fabric Attributes",
    ),
):
    """
    Cleans up devices with the _catch_all_ site in IP Fabric by updating their siteName attribute in IP Fabric.

    Args:
        subnet_source.json: A file containing the information about all subnets and their matching siteName.
    """

    if f_ipf_subnet(settings, subnet_source, update_ipf):
        logger.info("'Subnet Site Separation' task completed")
    else:
        logger.warning("'Subnet Site Separation' task failed")


@app.command("push", help="Update the site separation settings based on a CSV file.")
def push(
    file_source: typer.FileText = typer.Argument(
        ...,
        help="The CSV file containing the new site separation to apply.",
    ),
    attributes_list: List[str] = typer.Option(
        ["siteName"],
        "--attribute",
        "-a",
        help="Additional attributes to update in IP Fabric. Format: -a attribute1 -a attribute2",
    ),
):
    """
    Push the site separation settings based on a CSV file by updating their siteName attribute in IP Fabric.

    Args:
        file.csv: A file containing the new site separation to apply.
        file.xlsx: A file containing the new site separation to apply.
    """
    print(attributes_list)
    if f_push_attribute_from_file(settings, file_source, True, attributes_list):
        logger.info("'Push Site Separation from file' task completed")
    else:
        logger.warning("'Push Site Separation from file' task failed")


@app.command(
    "report", help="Create a report to find potential gaps in the Site Separation."
)
def report(
    file_output: str = typer.Argument(
        ...,
        help="Name of the file to output the report.",
    ),
    hostname_match: bool = typer.Option(
        False,
        "--hostname-match",
        "-h",
        help="Attempt matching devices based on similar hostname.",
    ),
):
    """
    Build a report with the following information:

    | device  | sn  | loginIP | Subnet (based on loginIP & mask) | ipf Site | sites matching the subnet       | suggestedFinalSite | FinalSite |
    | ------- | --- | ------- | -------------------------------- | -------- | ------------------------------- | ------------------ | --------- |
    | deviceA | snA | 1.1.1.1 | 1.1.1.0/26                       | site1    | [site1: 30, site2:50, site3:20] | site2              |           |

    Args:
        file_output: the (Excel) file where the report will be written.
    """

    if f_ipf_report_site_sep(settings, file_output, hostname_match):
        logger.info("'Report Site Separation' task completed")
    else:
        logger.warning("'Report Site Separation' task failed")


if __name__ == "__main__":
    app()
