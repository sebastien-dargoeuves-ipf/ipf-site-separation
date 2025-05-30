import os
import sys
from typing import List

import typer
from enum import Enum
from typing_extensions import Annotated
from loguru import logger

from modules.f_ipf import (
    f_ipf_catch_all,
    f_ipf_report_site_sep,
    f_ipf_subnet,
    f_ipf_rules_collect, # noqa: F401
    f_ipf_rules_update, # noqa: F401
    f_push_attribute_from_file,
)
from modules.f_snow import f_snow_site_sep
from modules.settings import Settings

settings = Settings()
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

class rulesActions(str, Enum):
    collect = "collect"
    update = "update"

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
    logger.info(f"IPF_URL: {settings.IPF_URL} | IPF_SNAPSHOT_ID: {settings.IPF_SNAPSHOT_ID}\n")


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


@app.command("subnet", help="Build Site Separation based on Subnet data provided in a json/csv file.")
def subnet(
    subnet_source: typer.FileText = typer.Argument(
        ...,
        help="The json/csv file containing the subnet information: [{value: 'site1', subnet: '1.1.1.0/24'}, ...]",
    ),
    attribute_to_update: str = typer.Option(
        "siteName",
        "--attribute",
        "-a",
        help="The attribute to update in IP Fabric. Default: siteName",
    ),
    update_ipf: bool = typer.Option(
        False,
        help="Dry Mode is default, if this option is enabled, it will update IP Fabric Attributes",
    ),
):
    """
    Cleans up devices with the _catch_all_ site in IP Fabric by updating their siteName attribute in IP Fabric.

    Args:
        subnet_source: A json/csv file containing the information about all subnets and their matching siteName.
    """

    if f_ipf_subnet(
        settings=settings, subnet_file=subnet_source, attribute_to_update=attribute_to_update, update_ipf=update_ipf
    ):
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
    update_only: bool = typer.Option(
        False,
        "--update",
        "-u",
        help="If set, the script will skip all fields where the final siteName is matching the original IPF siteName",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "-d",
        help="If set, the script will not update the IP Fabric attributes and generate a report instead.",
    ),
):
    """
    Push the site separation settings based on a CSV file by updating their siteName attribute in IP Fabric.

    Args:
        file.csv: A file containing the new site separation to apply.
        file.xlsx: A file containing the new site separation to apply.
    """
    if f_push_attribute_from_file(
        settings=settings,
        site_separation_file=file_source,
        update_only=update_only,
        dry_run=dry_run,
        attributes_list=attributes_list,
    ):
        logger.info("'Push Site Separation from file' task completed")
    else:
        logger.warning("'Push Site Separation from file' task failed")


@app.command("rules", help="Get or Update the site separation Rules")
def rules(
    action: Annotated[rulesActions, typer.Argument(
        case_sensitive=False,
        help=f"Action to perform: {rulesActions._member_names_}"
        )
    ] = rulesActions.collect,
    file_str: Annotated[str, typer.Option(
        "--file",
        "-f",
        help="File to (read from | write to) the site separation rules.",
    )] = "site_separation_rules.csv",
):
    """
    Collect the site separation rules from IP Fabric.
    or
    Push the site separation rules based on a CSV file.
    Args:
        action: The action to perform: collect or update
        input_file: A file containing the new site separation rules to apply.
        output_file: A file containing the current site separation rules.
    """

    # Check if the action has a valid function, and call it, otherwise raise an error
    action_method = getattr(sys.modules[__name__], f'f_ipf_rules_{action}', None)
    if callable(action_method):
        logger.info(f"Let's '{action}' the site separation rules...")
        if action_method(settings=settings, file_str=file_str):
            logger.info(f"'Rules {action}' task completed")
        else:
            logger.warning(f"'Rules {action}' task failed")
    else:
        logger.error(f"The function `f_ipf_rules_{action}` does not exist...")
        raise typer.Exit(code=1)



@app.command("report", help="Create a report to find potential gaps in the Site Separation.")
def report(
    file_output: str = typer.Argument(
        ...,
        help="Name of the file to output the report.",
    ),
    hostname_match: bool = typer.Option(
        False,
        "--hostname-match",
        "-hm",
        help="Attempt matching devices based on similar hostname.",
    ),
    connectivity_matrix_match: bool = typer.Option(
        False,
        "--connectivity-matrix-match",
        "-cmm",
        help="Attempt matching devices based on Connectivity Matrix Match.",
    ),
    recheck_site_sep: bool = typer.Option(
        False,
        "--recheck-site-sep",
        "-r",
        help="Recheck the Site Separation based on the calculated data.",
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

    if f_ipf_report_site_sep(
        settings,
        file_output,
        hostname_match,
        connectivity_matrix_match,
        recheck_site_sep,
    ):
        logger.info("'Report Site Separation' task completed")
    else:
        logger.warning("'Report Site Separation' task failed")


if __name__ == "__main__":
    app()
