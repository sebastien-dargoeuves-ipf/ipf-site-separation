import os

import typer
from loguru import logger

from modules.classDefinitions import Settings
from modules.functions import f_ipf_subnet

settings = Settings()
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


@app.callback()
def logging_configuration():
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

@app.command("subnet", help="Build Site Separation based on Subnet")
def subnet(
    subnet_source: typer.FileText = typer.Argument(
        ...,
        help="The file containing the subnet information.",
    ),
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
    import json
    try:
        subnet_data = json.load(subnet_source)
    except Exception as e:
        logger.error(f"Error loading file `{subnet_source}`, not a valid json. Error: {e}")
        return
    
    if f_ipf_subnet(settings, subnet_data, update_ipf):
        logger.info("'Subnet Site Separation' task completed")
    else:
        logger.warning("'Subnet Site Separation' task failed")


if __name__ == "__main__":
    app()


"""
# Delete local attributes
ipf_attributes = Attributes(client=ipf, snapshot_id="$last")
local_attrs = ipf_attributes.all()
ipf_attributes.delete_attribute(*local_attrs)
"""
