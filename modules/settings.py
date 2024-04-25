import os

from dotenv import find_dotenv, load_dotenv
from pydantic_settings import BaseSettings

load_dotenv(find_dotenv(), override=True)


class Settings(BaseSettings):
    """
    Represents the configuration settings for the site separation process.

    Explanation:
        This class defines the various settings required for the site separation process, such as IP Fabric URL,
        authentication token, ServiceNow credentials, and other related parameters.
    """

    IPF_URL: str = os.getenv("IPF_URL")
    IPF_TOKEN: str = os.getenv("IPF_TOKEN")
    IPF_SNAPSHOT_ID: str = os.getenv("IPF_SNAPSHOT_ID", "$last")
    IPF_VERIFY: bool = eval(os.getenv("IPF_VERIFY", "False").title())
    IPF_TIMEOUT: int = os.getenv("IPF_TIMEOUT", 20)

    SNOW_USER: str = os.getenv("SNOW_USER")
    SNOW_PASS: str = os.getenv("SNOW_PASS")
    SNOW_URL: str = os.getenv("SNOW_URL")
    SNOW_TIMEOUT: int = os.getenv("SNOW_TIMEOUT", 20)

    CATCH_ALL: str = "_catch_all_"
    PREFIX_FIXME: str = "_fixme_"
    SEARCH_NETWORK_PREFIX: int = 24
    MULTI_SITE_LIMIT: int = 50  # max length of the new siteName

    # Output folder
    OUTPUT_FOLDER: str = "output"
    # Report folder
    REPORT_FOLDER: str = "report"

    IPF_SNOW_MATCHED_FILENAME: str = "ipf_devices_found_in_snow.csv"
    IPF_SNOW_NOT_MATCHED_FILENAME: str = "ipf_devices_not_found_in_snow.csv"
    CATCH_ALL_FILENAME: str = "catch_all_remediation.csv"
    SUBNET_SITESEP_FILENAME: str = "subnets_site_separation.csv"
    IMPORT_SITESEP_FILENAME: str = "import_site_separation.csv"
