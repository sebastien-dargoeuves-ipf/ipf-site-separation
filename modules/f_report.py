import ipaddress


from loguru import logger

from modules.settings import Settings
from modules.utils import check_host_bits

try:
    from yaspin import yaspin

    YASPIN_ANIMATION = True
except ImportError:
    YASPIN_ANIMATION = False

MSG_NO_LOGINIP = "no loginIp"
MSG_SUBNET_NOT_FOUND = "subnet not found"


def create_site_sep_report(
    settings: Settings,
    ipf_devices: list,
    managed_ip_addresses: list,
    hostname_match: bool,
    connectivity_matrix_match: bool,
    connectivity_matrix: dict,
    recheck_site_sep: list,
) -> list:
    """
    Builds a Site Separation report based on the list of devices and their managed IP

    Args:
        ipf_devices: A list of dictionaries representing the IP Fabric devices,
        managed_ip_addresses: A list of dictionaries representing the managed IP addresses,
        file_output: Location where the file will be saved.

    Returns:
        Return a list of dictionnary containing the report information for each device.
    """

    def find_mgmt_subnet(ipf_devices, managed_ip_addresses):
        """
        Finds the management subnet for each device based on the provided IPF devices and managed IP addresses.

        Args:
            ipf_devices: A list of dictionaries representing IPF devices.
            managed_ip_addresses: A list of dictionaries representing managed IP addresses.

        Returns:
            A list of dictionaries representing IPF devices with the management subnet information added.
        """
        # Convert Managed IP table to dict with devices as keys and IP addresses to IP objects
        logger.debug(
            "Converting Managed IP table to dict with devices as keys and IP addresses to IP objects"
        )
        mip_dict = {}
        for mip in managed_ip_addresses:
            host_bit_check = check_host_bits(mip["net"])
            if not host_bit_check:
                continue
            mip["net"] = (
                ipaddress.IPv4Network(mip["net"], strict=True) if mip["net"] else None
            )
            if mip["hostname"] in mip_dict:
                mip_dict[mip["hostname"]].append(mip)
            else:
                mip_dict[mip["hostname"]] = [mip]

        logger.debug("Converting IP addresses in Device Inventory to IP objects")
        for device in ipf_devices:
            device["loginIp"] = (
                ipaddress.IPv4Address(device["loginIp"]) if device["loginIp"] else None
            )

        # Find the management subnet for each device
        logger.debug(
            "Finding the management subnet for each device, using loginIp and Managed IP table"
        )
        for device in ipf_devices:
            if not device["loginIp"]:
                device["net"] = MSG_NO_LOGINIP
                continue
            mips = mip_dict.get(device["hostname"], [])
            for mip in mips:
                if mip["net"] and device["loginIp"] in mip["net"]:
                    device["net"] = mip["net"]
                    break
            else:
                device["net"] = MSG_SUBNET_NOT_FOUND

        return ipf_devices

    def suggested_final_site(matching_sites):
        """
        Returns the suggested final site based on the matching sites.

        Args:
            matching_sites: A dictionary containing the matching sites for a subnet.

        Returns:
            The suggested final site.
        """
        if matching_sites:
            suggested_site = next(
                (
                    site
                    for site, data in matching_sites.items()
                    if data["percent"] >= 50
                ),
                "",
            )
            return suggested_site
        return ""

    def suggested_site_partial_name(hostname, hostname_to_site):
        """
        Returns the suggested site partial name based on the partial hostname.

        Args:
            partial_hostname: The partial hostname to search for.

        Returns:
            The suggested site partial name.
        """
        site_list = set()
        partial_hostname = hostname
        # hostname_to_site = {device["hostname"]: device["siteName"] for device in devices_report if device["hostname"] != hostname and device["siteName"] not in settings.UNKNOWN_SITES}

        while len(partial_hostname) > 5 and len(site_list) < 4:
            matching_sites = {
                site
                for host, site in hostname_to_site.items()
                if host.startswith(partial_hostname)
            }
            site_list.update(matching_sites)
            partial_hostname = partial_hostname[:-1]

        return site_list or "no site found based on hostname"

    def create_connectivity_matrix_dict(connectivity_matrix, hostname_to_site_dict):
        """
        Returns the suggested site based on the connectivity matrix.

        Args:
            sn: The serial number to search for.

        Returns:
            The suggested site based on the connectivity matrix.
        """
        # Create the dictionnary based on the connectivity matrix for each device
        hostname_connectivity_matrix_dict = {}

        # Iterate through the list of dictionaries
        for item in connectivity_matrix:
            local_host = item["localHost"]
            remote_host = item["remoteHost"]
            protocol = item["protocol"]

            # Update the dictionary for local host
            if local_host in hostname_connectivity_matrix_dict:
                hostname_connectivity_matrix_dict[local_host].append(
                    {
                        "device": remote_host,
                        "protocol": protocol,
                        "remoteSite": hostname_to_site_dict.get(remote_host),
                    }
                )
            else:
                hostname_connectivity_matrix_dict[local_host] = [
                    {
                        "device": remote_host,
                        "protocol": protocol,
                        "remoteSite": hostname_to_site_dict.get(remote_host),
                    }
                ]

            # Update the dictionary for remote host
            if remote_host in hostname_connectivity_matrix_dict:
                hostname_connectivity_matrix_dict[remote_host].append(
                    {
                        # "device": local_host,
                        "protocol": protocol,
                        "remoteSite": hostname_to_site_dict.get(remote_host),
                    }
                )
            else:
                hostname_connectivity_matrix_dict[remote_host] = [
                    {
                        # "device": local_host,
                        "protocol": protocol,
                        "remoteSite": hostname_to_site_dict.get(remote_host),
                    }
                ]

        return hostname_connectivity_matrix_dict

    def suggested_site_connectivity_matrix(hostname, hostname_connectivity_matrix_dict):
        """
        Returns the suggested site based on the connectivity matrix.

        Args:
            sn: The serial number to search for.

        Returns:
            The suggested site based on the connectivity matrix.
        """
        site_list = set()
        if hostname in hostname_connectivity_matrix_dict:
            site_list = {
                sites["remoteSite"]
                for sites in hostname_connectivity_matrix_dict[hostname]
                if sites["remoteSite"]
            }
        return site_list or "no site found based on connectivity matrix"

    def create_subnet_all_site_report(devices_report):
        """
        Creates a subnet site report based on the provided report data.

        Args:
            report: A list of dictionaries representing site entries.

        Returns:
            A dictionary containing the subnet site report with entry statistics.
        """
        from collections import defaultdict

        site_entry_count = defaultdict(lambda: defaultdict(int))

        # Count the number of devices for each site in each subnet
        # logger.debug("Counting the number of devices for each site in each subnet")
        for entry in devices_report:
            site_name = entry["siteName"]
            if entry["net"] in [MSG_NO_LOGINIP, MSG_SUBNET_NOT_FOUND]:
                continue
            net = entry["net"]
            site_entry_count[net][site_name] += 1

        subnet_report = {}
        logger.debug("Calculating the entry statistics for each subnet")
        for subnet, sites in site_entry_count.items():
            entry_stats = {
                net: {
                    "count": count,
                    "percent": float(f"{count / sum(sites.values()) * 100:.2f}"),
                }
                for net, count in sites.items()
            }
            subnet_report[subnet] = entry_stats

        return subnet_report

    def create_subnet_site_report(settings: Settings, devices_report: list):
        """
        Creates a subnet site report based on the provided report data.

        Args:
            report: A list of dictionaries representing site entries.

        Returns:
            A dictionary containing the subnet site report with entry statistics.
        """
        from collections import defaultdict

        site_entry_count = defaultdict(lambda: defaultdict(int))

        # Count the number of devices for each site in each subnet
        # logger.debug("Counting the number of devices for each site in each subnet")
        for entry in devices_report:
            site_name = entry["siteName"]
            if entry["net"] in [MSG_NO_LOGINIP, MSG_SUBNET_NOT_FOUND]:
                continue
            net = entry["net"]
            site_entry_count[net][site_name] += 1

        subnet_report = {}
        logger.debug("Calculating the entry statistics for each subnet")
        for subnet, sites in site_entry_count.items():
            filtered_sites = {
                site: count
                for site, count in sites.items()
                if site not in settings.UNKNOWN_SITES
            }

            entry_stats = {
                site: {
                    "count": count,
                    "percent": float(
                        f"{count / sum(filtered_sites.values()) * 100:.2f}"
                    ),
                }
                for site, count in filtered_sites.items()
            }
            subnet_report[subnet] = entry_stats

        return subnet_report or ""

    # Find the management subnet for each device
    logger.info("Finding the management subnet for each device...")
    if not recheck_site_sep:
        devices_report = find_mgmt_subnet(ipf_devices, managed_ip_addresses)
        site_name_column = "siteName"
    else:
        devices_report = recheck_site_sep
        site_name_column = "siteName2"
    # Create the table containing all sites for each management subnet
    subnet_all_site_report = create_subnet_all_site_report(devices_report)
    subnet_site_report = create_subnet_site_report(settings, devices_report)
    logger.info("... and putting the data together")
    if YASPIN_ANIMATION and (hostname_match or connectivity_matrix_match):
        sp = yaspin(
            text="Putting the data together",
            color="yellow",
            timer=True,
        )
        sp.start()
    hostname_to_site_dict = {
        device["hostname"]: device["siteName"]
        for device in devices_report
        if device["siteName"] not in settings.UNKNOWN_SITES
    }
    if connectivity_matrix_match:
        hostname_connectivity_matrix_dict = create_connectivity_matrix_dict(
            connectivity_matrix, hostname_to_site_dict
        )

    for device in devices_report:
        if recheck_site_sep:
            device["IPFSiteName"] = device.pop("currentSiteName")
        device["currentSiteName"] = device.pop("siteName")
        device["matchingAllSites"] = subnet_all_site_report.get(device["net"])
        device["matchingSites"] = subnet_site_report.get(device["net"])
        # device["suggestedAllSite"] = suggested_final_site(device["matchingAllSites"])
        device["suggestedSite"] = suggested_final_site(device["matchingSites"])

        device["suggestedSite eq currentSiteName"] = (
            device["suggestedSite"] == device["currentSiteName"]
        )

        device[site_name_column] = ""

        if device["suggestedSite eq currentSiteName"]:
            device[site_name_column] = device["suggestedSite"]
        elif (
            device["suggestedSite"]
            and device["currentSiteName"] in settings.UNKNOWN_SITES
        ):
            device[site_name_column] = device["suggestedSite"]

        device["#"] = "#"

        if hostname_match and (
            (device["currentSiteName"] in settings.UNKNOWN_SITES)
            or (not device["suggestedSite"])
            or (not device["suggestedSite eq currentSiteName"])
        ):
            device["site based on hostname"] = suggested_site_partial_name(
                device["hostname"], hostname_to_site_dict
            )
            if (
                len(device["site based on hostname"]) == 1
                and not device[site_name_column]
            ):
                unique_site = device["site based on hostname"].pop()
                device["site based on hostname"] = unique_site
                device[site_name_column] = unique_site

        if connectivity_matrix_match and (
            (device["currentSiteName"] in settings.UNKNOWN_SITES)
            or (not device["suggestedSite"])
            or (not device["suggestedSite eq currentSiteName"])
        ):
            device["site based on connectivity_matrix"] = (
                suggested_site_connectivity_matrix(
                    device["hostname"], hostname_connectivity_matrix_dict
                )
            )
            if (
                len(device["site based on connectivity_matrix"]) == 1
                and not device[site_name_column]
            ):
                unique_site = device["site based on connectivity_matrix"].pop()
                device["site based on connectivity_matrix"] = unique_site
                device[site_name_column] = unique_site

    if YASPIN_ANIMATION and (hostname_match or connectivity_matrix_match):
        sp.ok("✅ ")
    return devices_report
