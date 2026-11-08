import argparse
import ipaddress
import logging
import os
import re
import sys

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class VirusTotalAPI:
    """
    A class to interact with the VirusTotal API.
    """

    def __init__(self, api_key):
        """
        Initializes the VirusTotalAPI class.

        Args:
            api_key (str): The VirusTotal API key.
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.last_status = None
        self.last_error_kind = None

    def get_ip_report(self, ip_address):
        """
        Retrieves a report for a given IP address from VirusTotal.

        Args:
            ip_address (str): The IP address to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"ip_addresses/{ip_address}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            self.last_status = response.status_code
            if response.status_code == 404:
                self.last_error_kind = "not_found"
                return None
            if response.status_code in (401, 403, 429) or response.status_code >= 400:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal lookup failed with HTTP {response.status_code} for {url}")
                return None
            self.last_error_kind = None
            try:
                return response.json()
            except ValueError as e:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal returned a non-JSON response for {url}: {e}")
                return None
        except requests.exceptions.RequestException as e:
            self.last_error_kind = "failed"
            logging.error(f"Error querying VirusTotal for IP {ip_address}: {e}")
            return None

    def get_domain_report(self, domain):
        """
        Retrieves a report for a given domain from VirusTotal.

        Args:
            domain (str): The domain to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"domains/{domain}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            self.last_status = response.status_code
            if response.status_code == 404:
                self.last_error_kind = "not_found"
                return None
            if response.status_code in (401, 403, 429) or response.status_code >= 400:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal lookup failed with HTTP {response.status_code} for {url}")
                return None
            self.last_error_kind = None
            try:
                return response.json()
            except ValueError as e:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal returned a non-JSON response for {url}: {e}")
                return None
        except requests.exceptions.RequestException as e:
            self.last_error_kind = "failed"
            logging.error(f"Error querying VirusTotal for domain {domain}: {e}")
            return None

    def get_file_report(self, file_hash):
        """
        Retrieves a report for a given file hash from VirusTotal.

        Args:
            file_hash (str): The file hash (MD5, SHA1, or SHA256) to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"files/{file_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            self.last_status = response.status_code
            if response.status_code == 404:
                self.last_error_kind = "not_found"
                return None
            if response.status_code in (401, 403, 429) or response.status_code >= 400:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal lookup failed with HTTP {response.status_code} for {url}")
                return None
            self.last_error_kind = None
            try:
                return response.json()
            except ValueError as e:
                self.last_error_kind = "failed"
                logging.error(f"VirusTotal returned a non-JSON response for {url}: {e}")
                return None
        except requests.exceptions.RequestException as e:
            self.last_error_kind = "failed"
            logging.error(f"Error querying VirusTotal for hash {file_hash}: {e}")
            return None


def is_valid_ip(ip_address):
    """
    Validates if the given string is a valid IPv4 address.

    Args:
        ip_address (str): The string to validate.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    # Parse with the standard library address parser instead of int():
    # int() accepted shapes a real parser rejects, such as a leading
    # plus ("+8.8.8.8"), spaces (" 8.8.8.8"), underscores ("1_0.0.0.1"),
    # and leading zeros ("008.8.8.8"), so those were sent to the API as
    # if they were valid addresses. IPv4Address rejects all of them.
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    """
    Validates if the given string is a valid domain.

    Requires at least two dot separated labels, each label made of
    letters, digits, or hyphens and not starting or ending with a
    hyphen, and a final label of at least two letters.

    Args:
        domain (str): The string to validate.

    Returns:
        bool: True if the string is a valid domain, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False
    return re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}", domain) is not None


def is_valid_hash(file_hash):
    """
    Validates if the given string is a valid MD5, SHA1, or SHA256 hash.  Uses length checks.

    Args:
        file_hash (str): The string to validate.

    Returns:
        bool: True if the string is a valid hash, False otherwise.
    """
    if len(file_hash) not in (32, 40, 64):
        return False
    return re.fullmatch(r"[0-9a-fA-F]+", file_hash) is not None


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Enriches an IP address, domain, or hash with context from VirusTotal."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--ip", help="IP address to lookup"
    )  # Changed to -i for brevity and common usage
    group.add_argument(
        "-d", "--domain", help="Domain to lookup"
    )  # Changed to -d for brevity
    group.add_argument(
        "-f", "--file", help="File hash (MD5, SHA1, SHA256) to lookup"
    )  # Changed to -f for brevity
    parser.add_argument(
        "-k",
        "--apikey",
        help="VirusTotal API key. Can also be set via environment variable VIRUSTOTAL_API_KEY.",
    )  # Added -k for brevity and to allow setting API key from env
    parser.add_argument(
        "-o", "--output", help="Output file to save the report (optional)"
    )  # Added -o for outputting to file

    return parser


def analyze_ip(vt_api, ip_address, output_file=None):
    """
    Analyzes an IP address using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        ip_address (str): The IP address to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_ip_report(ip_address)

    if not report or "error" in report or "data" not in report:
        if report and ("error" in report or "data" not in report):
            print(f"VirusTotal lookup failed for IP address: {report.get('error', {}).get('message', 'error response with no data') if isinstance(report, dict) else 'error response'}")
        elif getattr(vt_api, "last_error_kind", None) == "not_found":
            print(f"No VirusTotal report found for IP address: {ip_address}")
        else:
            print(f"VirusTotal lookup failed for IP address: {ip_address}")
        return False

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        reputation = attributes.get("reputation", 0)

        output = f"IP Address: {ip_address}\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"
        output += f"  Total Votes (Harmless): {total_votes.get('harmless', 0)}\n"
        output += f"  Total Votes (Malicious): {total_votes.get('malicious', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            # The first five engines are whatever order the response mapping happens to carry.
            # Nothing ranks them, so the five shown can change between runs on the same input.
            )[:5]:  # Limit to first 5 results
                category = result.get("category", "unknown") if isinstance(result, dict) else "unknown"
                result_text = result.get("result", "") if isinstance(result, dict) else ""
                output += f"    {engine}: {category} ({result_text})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")
                return False

    return True


def analyze_domain(vt_api, domain, output_file=None):
    """
    Analyzes a domain using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        domain (str): The domain to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_domain_report(domain)

    if not report or "error" in report or "data" not in report:
        if report and ("error" in report or "data" not in report):
            print(f"VirusTotal lookup failed for domain: {report.get('error', {}).get('message', 'error response with no data') if isinstance(report, dict) else 'error response'}")
        elif getattr(vt_api, "last_error_kind", None) == "not_found":
            print(f"No VirusTotal report found for domain: {domain}")
        else:
            print(f"VirusTotal lookup failed for domain: {domain}")
        return False

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        output = f"Domain: {domain}\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            )[:5]:  # Limit to first 5 results
                category = result.get("category", "unknown") if isinstance(result, dict) else "unknown"
                result_text = result.get("result", "") if isinstance(result, dict) else ""
                output += f"    {engine}: {category} ({result_text})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")
                return False

    return True


def analyze_file(vt_api, file_hash, output_file=None):
    """
    Analyzes a file hash using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        file_hash (str): The file hash to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_file_report(file_hash)

    if not report or "error" in report or "data" not in report:
        if report and ("error" in report or "data" not in report):
            print(f"VirusTotal lookup failed for hash: {report.get('error', {}).get('message', 'error response with no data') if isinstance(report, dict) else 'error response'}")
        elif getattr(vt_api, "last_error_kind", None) == "not_found":
            print(f"No VirusTotal report found for hash: {file_hash}")
        else:
            print(f"VirusTotal lookup failed for hash: {file_hash}")
        return False

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)
        names = attributes.get("names", [])
        type_description = attributes.get("type_description", "N/A")
        size = attributes.get("size", "N/A")

        output = f"File Hash: {file_hash}\n"
        output += f"  Names: {', '.join(names) if names else 'N/A'}\n"
        output += f"  Type Description: {type_description}\n"
        output += f"  Size: {size} bytes\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            )[:5]:  # Limit to first 5 results
                category = result.get("category", "unknown") if isinstance(result, dict) else "unknown"
                result_text = result.get("result", "") if isinstance(result, dict) else ""
                output += f"    {engine}: {category} ({result_text})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")
                return False

    return True


def main():
    """
    Main function to drive the threat context enrichment process.
    """

    parser = setup_argparse()
    args = parser.parse_args()

    # Get API key from command line or environment variable
    api_key = args.apikey or os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        logging.error(
            "VirusTotal API key is required. Provide it via --apikey or VIRUSTOTAL_API_KEY environment variable."
        )
        sys.exit(1)

    vt_api = VirusTotalAPI(api_key)

    if args.ip:
        if is_valid_ip(args.ip):
            if not analyze_ip(vt_api, args.ip, args.output):
                sys.exit(1)
        else:
            logging.error("Invalid IP address.")
            sys.exit(1)
    elif args.domain:
        if is_valid_domain(args.domain):
            if not analyze_domain(vt_api, args.domain, args.output):
                sys.exit(1)
        else:
            logging.error("Invalid domain.")
            sys.exit(1)
    elif args.file:
        if is_valid_hash(args.file):
            if not analyze_file(vt_api, args.file, args.output):
                sys.exit(1)
        else:
            logging.error("Invalid file hash.")
            sys.exit(1)


if __name__ == "__main__":
    main()