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

    SNOW_USER: str = os.getenv("SNOW_USER")
    SNOW_PASS: str = os.getenv("SNOW_PASS")
    SNOW_URL: str = os.getenv("SNOW_URL")
    SNOW_TIMEOUT: int = os.getenv("SNOW_TIMEOUT", 20)

    CATCH_ALL = "_catch_all_"
    PREFIX_FIXME = "_fixme_"
    SEARCH_NETWORK_PREFIX = 24
    MULTI_SITE_LIMIT = 50  # max length of the new siteName
