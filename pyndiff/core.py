#!/usr/bin/env python
"""
Generate human-readable ndiff output when comparing 2 Nmap XML scan files.

ndiff overview: https://nmap.org/book/ndiff-man.html

# Normal installation process, however, ndiff is only Python2 compatible.
git clone https://github.com/nmap/nmap.git
cd nmap/ndiff/
sudo python setup.py install

See PR-1807 (https://github.com/nmap/nmap/pull/1807) for a Python3 compatible ndiff.  Until PR-1807 is merged into
master, the individual ndiff.py can be retrieved manually at:

https://github.com/nmap/nmap/pull/1807/files#diff-876b1aeeb590be439b50702351985b633655e89e78f6b520f321ce84076c6b32

wget https://raw.githubusercontent.com/nmap/nmap/82f8b1a95c2b2adcea36c6cfc51e5ea4d6fc6211/ndiff/ndiff.py
"""

# Standard Python libraries.
import argparse
import io
import json
import os
import time
import traceback
from xml.etree.cElementTree import fromstring

# Third party Python libraries.
from . import ndiff  # See note above for source of file.
import xmljson

# Custom Python libraries.

__version__ = "1.0.0"


def build_nmap_service_name(service_dict):
    """Build Nmap service name."""

    nmap_service_name = ""

    service_name = service_dict.get("name", "")
    service_product = service_dict.get("product", "")
    service_version = service_dict.get("version", "")
    service_extrainfo = service_dict.get("extrainfo", "")

    nmap_service_name = f"{service_name} {service_product} {service_version} {service_extrainfo}".replace(
        "  ", " "
    ).strip()

    return nmap_service_name


def generate_diff(
    xml_file_a,
    xml_file_b,
    ignore_udp_open_filtered=False,
    output_type="xml",
    write_summary_to_disk_for_xml_output_type=False,
    verbose=False,
    step_debug=False,
):

    start_time = time.time()

    if output_type not in ["txt", "xml"]:
        print(f'Invalid output type: "{output_type}".  Must be "txt" or "xml"')
        return None

    if not os.path.exists(xml_file_a):
        print(f"File does not exist: {xml_file_a}")
        return None

    if not os.path.exists(xml_file_b):
        print(f"File does not exist: {xml_file_b}")
        return None

    if xml_file_a == xml_file_b:
        print("Provided scan files are the same, they must be different.")
        return None

    # Load XML scan data from files.
    try:
        print(f'Loading scan "a" file: {xml_file_a}')
        scan_a = ndiff.Scan()
        scan_a.load_from_file(xml_file_a)
        print(f'Successfully loaded scan "a" file: {xml_file_a}')
    except Exception as e:
        print(f"Exception loading {xml_file_a}: {e}")
        return None

    try:
        print(f'Loading scan "b" file: {xml_file_b}')
        scan_b = ndiff.Scan()
        scan_b.load_from_file(xml_file_b)
        print(f'Successfully loaded scan "b" file: {xml_file_b}')
    except Exception as e:
        print(f"Exception loading {xml_file_b}: {e}")
        return None

    # Generate the diff file basename to be used.
    xml_file_a_basefile_name = os.path.splitext(os.path.basename(xml_file_a))[0]
    xml_file_b_basefile_name = os.path.splitext(os.path.basename(xml_file_b))[0]
    diff_file_basename = f"{xml_file_a_basefile_name}_DIFF_{xml_file_b_basefile_name}"

    # TXT
    if output_type == "txt":
        # Text output like the ndiff --text switch uses.  Not easy to analyze for large diffs, but including this as an
        # option to return. Easiest to write to a file, read it, and return the string.

        try:
            txt_stream = io.StringIO()
            diff = ndiff.ScanDiffText(scan_a, scan_b, txt_stream)
            # The .output() function writes output to txt_stream.
            cost = diff.output()

            print(f"ndiff cost: {cost}")

        except Exception as e:
            print(f"Exception: {e}.  Issue writting ndiff TXT output to a io.StringIO object.")
            return None

        scan_summary = txt_stream.getvalue()

        print(scan_summary)

        return scan_summary

    # XML
    try:
        xml_stream = io.StringIO()
        diff = ndiff.ScanDiffXML(scan_a, scan_b, xml_stream)
        # The .output() function writes output to xml_stream.
        cost = diff.output()

        print(f"ndiff cost: {cost}")

    except Exception as e:
        print(f"Exception: {e}.  Issue writting ndiff XML output to a io.StringIO object.")
        return None

    # Convert from XML to a JSON object for easier parsing.
    try:
        xmljson_object = xmljson.XMLData()
        xmljson_object_as_string = xmljson_object.data(fromstring(xml_stream.getvalue()))
        json_data = json.loads(json.dumps(xmljson_object_as_string))

    except Exception as e:
        print(f"Exception: {e}.  Issue converting XML to JSON.")
        return None

    # Extract Nmap stats.
    a_stats = json_data["nmapdiff"]["scandiff"]["a"]["nmaprun"]
    b_stats = json_data["nmapdiff"]["scandiff"]["b"]["nmaprun"]

    # Calculate time math.
    scan_delta_seconds = b_stats["start"] - a_stats["start"]
    scan_delta_minutes = round(scan_delta_seconds / 60, 2)
    scan_delta_hours = round(scan_delta_minutes / 60, 2)
    scan_delta_days = round(scan_delta_hours / 24, 2)

    # Initialize change summary text with scan stat info.
    change_summary = f"""Scan summary

Previous scan start time: {a_stats['startstr']}
Latest scan start time:   {b_stats['startstr']}
Time between scans: {scan_delta_seconds} seconds / {scan_delta_minutes} minutes / {scan_delta_hours} hours / {scan_delta_days} days

"""

    hostdiff_raw = json_data["nmapdiff"]["scandiff"]["hostdiff"]

    # Standardize hostdiff to be a list so it can be iterated through.
    # Single host (dict object) - add hostdiff dict to an empty list so it can be iterated through.
    if type(hostdiff_raw) is dict:
        hostdiff = []
        hostdiff.append(hostdiff_raw)
    # Multiple hosts (list of dicts) - hostdiff is already a list of dicts.
    else:
        hostdiff = hostdiff_raw

    """
    Order of diff checks:

    1) Host online/offline state detection with updated port status.
    2) Service name change detection on port.
    3) Port status change detection on host.

    This was a beast to get to a decent state.  There may be some fringe edge cases that may not work or provide a
    correct assessment of the scan diff.  Best way to analyze is to use the -d and -v switches to step through each diff
    and inspect manually.
    """

    # Track any scan events in this variable.
    scan_events = ""

    # Iterate through the hosts.
    for host in hostdiff:

        if verbose:
            print("=" * 10)
            print(f"Host:\n{json.dumps(host, indent=4)}")
            print("Events:")

        try:

            # 1) Host online/offline state detection.
            # Host returned a port status (closed, open) for scan "a", but not for scan "b", so it's offline.
            if "a" in host:

                if host["a"]["host"]["status"]["state"] == "up":
                    target = host["a"]["host"]["address"]["addr"]

                    # 1) Determine which ports are now closed, if any.
                    try:
                        port_raw = host["a"]["host"]["ports"]["port"]
                    # Host could be up from an ICMP echo reply and not necessarily have any closed ports.
                    except KeyError:
                        continue

                    # For a single port, add port_raw dict to empty list so it can iterated through.
                    if type(port_raw) is dict:
                        port_raw_list = []
                        port_raw_list.append(port_raw)
                    # For multiple ports, port_raw is already a list of dicts.
                    else:
                        port_raw_list = port_raw

                    for port in port_raw_list:

                        protocol = port["protocol"].upper()
                        portid = port["portid"]
                        state = port["state"]["state"]

                        if ignore_udp_open_filtered:
                            if protocol == "UDP" and state == "open|filtered":
                                continue

                        # Don't bother showing explicit closed ports.
                        if state == "closed":
                            continue

                        # Host is down, so every port is now closed.
                        event = f"{target} port {protocol} {portid} is closed"
                        if verbose:
                            print(f"1a - {event}")
                            if step_debug:
                                input("Press Enter to continue...")
                        scan_events += f"{event}\n"

                    # 2) Just notify that the host is offline with non-specified ports.  Not as useful.
                    # event = f"{target} is offline"
                    # if verbose:
                    #     print(f"1a - {event}")
                    #     input("Press Enter to continue...")
                    # scan_events += f"{event}\n"

                    continue

            # Host returned a port status (closed, open) for scan "b", but not for scan "a", so it's online.
            if "b" in host:

                if host["b"]["host"]["status"]["state"] == "up":
                    target = host["b"]["host"]["address"]["addr"]

                    # 1) Determine which ports are now open, if any.
                    try:
                        port_raw = host["b"]["host"]["ports"]["port"]
                    # Host could be up from an ICMP echo reply and not necessarily have any open ports.
                    except KeyError:
                        continue

                    # For a single port, add port_raw dict to empty list so it can iterated through.
                    if type(port_raw) is dict:
                        port_raw_list = []
                        port_raw_list.append(port_raw)
                    # For multiple ports, port_raw is already a list of dicts.
                    else:
                        port_raw_list = port_raw

                    for port in port_raw_list:

                        protocol = port["protocol"].upper()
                        portid = port["portid"]
                        state = port["state"]["state"]

                        if ignore_udp_open_filtered:
                            if protocol == "UDP" and state == "open|filtered":
                                continue

                        # Don't bother showing explicit closed ports.
                        if state == "closed":
                            continue

                        # Build the service name of the new online port.
                        service_dict = port["service"]
                        nmap_service_name = build_nmap_service_name(service_dict)

                        event = f'{target} port {protocol} {portid} is {state} with service "{nmap_service_name}"'
                        if verbose:
                            print(f"1b - {event}")
                            if step_debug:
                                input("Press Enter to continue...")
                        scan_events += f"{event}\n"

                    # 2) Just notify that the host is online with non-specified ports.  Not as useful.
                    # event = f"{target} is online"
                    # if verbose:
                    #     print(f"1b - {event}")
                    #     input("Press Enter to continue...")
                    # scan_events += f"{event}\n"

                    continue

            # Move on if there is no portdiff to analyze.  This could include an operating system change which might
            # be added later.
            if "portdiff" not in host["host"]["ports"]:
                continue

            # Extract the target.
            target = host["host"]["address"]["addr"]

            # Extract the portdiff dict.
            portdiff_raw = host["host"]["ports"]["portdiff"]

            # For a single port, add portdiff dict to empty list so it can be iterated through.
            if type(portdiff_raw) is dict:
                portdiffs = []
                portdiffs.append(portdiff_raw)
            # For multiple ports, portdiff is already a list of dicts.
            else:
                portdiffs = portdiff_raw

            for portdiff in portdiffs:

                # 2) Service name change detection.
                if "b" not in portdiff:

                    port = portdiff["port"]["portid"]
                    protocol = portdiff["port"]["protocol"].upper()

                    # Build complete "a" service name.
                    service_dict_a = portdiff["port"]["a"]["service"]
                    portdiff_a_service = build_nmap_service_name(service_dict_a)

                    # Build complete "b" service name.
                    service_dict_b = portdiff["port"]["b"]["service"]
                    portdiff_b_service = build_nmap_service_name(service_dict_b)

                    event = f'{target} {protocol} {port} service changed from "{portdiff_a_service}" to "{portdiff_b_service}"'

                    if verbose:
                        print(f"2 - {event}")
                        if step_debug:
                            input("Press Enter to continue...")

                    scan_events += f"{event}\n"

                    continue

                # 3) Port status change detection.  Use "b" scan as source of truth to determine if a port state changed.
                b_dict = portdiff["b"]["port"]
                b_dict_port = b_dict["portid"]
                b_dict_protocol = b_dict["protocol"].upper()

                # Add explicit "closed" state to b_dict, having the dictionary reflect what is in the
                # portdiff["a"]["port"] dictionary.
                a_dict = portdiff["a"]["port"]

                # TODO doublecheck this logic.
                if "state" not in b_dict and "state" in a_dict:
                    if a_dict["state"]["state"] != "closed":
                        b_dict["state"] = {}
                        b_dict["state"]["state"] = "closed"

                    else:
                        continue

                b_dict_state = b_dict["state"]["state"]

                # Ignore UDP ports that aren't definitively "open".  Ignores if either scan a or b have a UDP port with
                # the "open|filtered" state.
                if ignore_udp_open_filtered:

                    if b_dict_protocol == "UDP" and b_dict_state == "open|filtered":
                        continue

                    # Ignore state changes from when a's scan is UDP "open|filtered".
                    a_dict = portdiff["a"]["port"]
                    a_dict_protocol = a_dict["protocol"].upper()

                    try:
                        a_dict_state = a_dict["state"]["state"]
                    except KeyError:
                        a_dict_state = "closed"

                    if a_dict_protocol == "UDP" and a_dict_state == "open|filtered":
                        continue

                event = f"{target} {b_dict_protocol} {b_dict_port} changed state to {b_dict_state}"

                # Build the service name of the new online port.
                if b_dict_state == "open":
                    service_dict = b_dict["service"]
                    nmap_service_name = build_nmap_service_name(service_dict)
                    event += f' with service "{nmap_service_name}"'

                if verbose:
                    print(f"3 - {event}")
                    if step_debug:
                        input("Press Enter to continue...")

                scan_events += f"{event}\n"

        except Exception as e:
            print(f"Exception: {e}.  Issue processing: {json.dumps(host, indent=4)}")
            traceback.print_exc()
            return None

    # Determine total processing time.
    finish_time = time.time()
    total_processing_time = round(finish_time - start_time, 2)
    total_processing_time_message = f"Total processing time: {total_processing_time} seconds\n\n"
    print(total_processing_time_message)
    change_summary += f"{total_processing_time_message}"

    # Determine final change summary results.
    if not scan_events:
        change_summary += "No scan diff detected between scans."
    else:
        change_summary += scan_events

    # Print out change summary.
    print("=" * 30)
    print(change_summary)

    # Optionally write the results to a file.
    if write_summary_to_disk_for_xml_output_type:
        change_summary_file_name = f"{diff_file_basename}.summary"
        with open(change_summary_file_name, "w") as fh:
            fh.write(change_summary)

    return change_summary


def parse_args():

    parser = argparse.ArgumentParser(
        description="Generate human-readable ndiff output when comparing 2 Nmap XML scan files."
    )
    parser.add_argument(
        "-d",
        dest="step_debug",
        action="store_true",
        default=False,
        required=False,
        help="Stop processing after every diff to validate results only when the -v switch is used.",
    )
    parser.add_argument("-f1", dest="xml_file_a", action="store", required=True, help='Nmap XML file "a"')
    parser.add_argument("-f2", dest="xml_file_b", action="store", required=True, help='Nmap XML file "b"')
    parser.add_argument(
        "--uof",
        dest="ignore_udp_open_filtered",
        action="store_true",
        default=False,
        help='Ignore UDP "open|filtered" port state changes because they aren\'t definitive.',
    )
    parser.add_argument(
        "-s",
        dest="write_summary_to_disk_for_xml_output_type",
        action="store_true",
        default=False,
        help="Write the summary result file to disk if '-t xml' is specified.",
    )
    parser.add_argument(
        "-t",
        dest="output_type",
        action="store",
        default="xml",
        required=False,
        help="ndiff output type: xml or txt.  Default is xml.",
    )
    parser.add_argument(
        "-v",
        dest="verbose",
        action="store_true",
        default=False,
        help="Print verbose data for troubleshooting.  Helpful when used in with -d",
    )
    args = parser.parse_args()

    return args


if __name__ == "__main__":
    args = parse_args()
    generate_diff(**vars(args))
