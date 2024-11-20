import os
import requests
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import random
from statistics import mean, median, stdev
import pandas as pd
import traceback
import re


def create_fattree_topology(k=4, density=2):
    """
    Create a Fat-Tree topology with specified parameters.

    Args:
        k (int): Parameter defining the size of the Fat-Tree.
        density (int): Number of hosts per edge switch.

    Returns:
        net (Mininet): The initialized Mininet network.
        hosts (dict): Dictionary of host objects.
        switches (dict): Dictionary of switch objects.
        dpid_to_switch (dict): Mapping from DPID integers to switch names.
    """
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Calculate the number of switches
    num_core = (k // 2) ** 2
    num_agg = (k ** 2) // 2
    num_edge = (k ** 2) // 2
    num_hosts = num_edge * density

    info(f"Creating Fat-Tree Topology with k={k}, density={density}\n")
    info(f"Number of Core Switches: {num_core}\n")
    info(f"Number of Aggregation Switches: {num_agg}\n")
    info(f"Number of Edge Switches: {num_edge}\n")
    info(f"Number of Hosts: {num_hosts}\n")

    # Create switches
    switches = {}
    dpid_to_switch = {}

    # Assign DPIDs starting from 1 for Core, then Aggregation, then Edge
    current_dpid = 1

    # Core Switches
    for i in range(1, num_core + 1):
        switch_name = f'c{i}'
        dpid = format(current_dpid, '016x')
        switches[switch_name] = net.addSwitch(
            switch_name,
            cls=OVSKernelSwitch,
            protocols='OpenFlow13',
            stp=False,
            dpid=dpid
        )
        dpid_to_switch[current_dpid] = switch_name
        info(f"Added Core Switch {switch_name} with DPID {dpid}\n")
        current_dpid += 1

    # Aggregation Switches
    for i in range(1, num_agg + 1):
        switch_name = f'a{i}'
        dpid = format(current_dpid, '016x')
        switches[switch_name] = net.addSwitch(
            switch_name,
            cls=OVSKernelSwitch,
            protocols='OpenFlow13',
            stp=False,
            dpid=dpid
        )
        dpid_to_switch[current_dpid] = switch_name
        info(f"Added Aggregation Switch {switch_name} with DPID {dpid}\n")
        current_dpid += 1

    # Edge Switches
    for i in range(1, num_edge + 1):
        switch_name = f'e{i}'
        dpid = format(current_dpid, '016x')
        switches[switch_name] = net.addSwitch(
            switch_name,
            cls=OVSKernelSwitch,
            protocols='OpenFlow13',
            stp=False,
            dpid=dpid
        )
        dpid_to_switch[current_dpid] = switch_name
        info(f"Added Edge Switch {switch_name} with DPID {dpid}\n")
        current_dpid += 1

    # Create hosts
    hosts = {}
    for i in range(1, num_hosts + 1):
        host_name = f'h{i}'
        ip_address = f'10.0.{(i - 1) // density}.{(i - 1) % density + 1}'
        hosts[host_name] = net.addHost(host_name, ip=ip_address)
        info(f"Added Host {host_name} with IP {ip_address}\n")

    # Connect Core to Aggregation
    for pod in range(1, k + 1):
        for agg in range(1, k // 2 + 1):
            agg_switch = f'a{(pod - 1) * (k // 2) + agg}'
            for core_group in range(1, k // 2 + 1):
                core_switch = f'c{(core_group - 1) * (k // 2) + agg}'
                if core_switch not in switches:
                    info(f"Warning: Core switch {core_switch} does not exist. Skipping connection.\n")
                    continue
                net.addLink(
                    switches[core_switch],
                    switches[agg_switch],
                    cls=TCLink,
                    bw=10,
                    delay='20ms'
                )
                info(f"Connected {core_switch} to {agg_switch} with 10Mbps, 20ms delay\n")

    # Connect Aggregation to Edge
    for pod in range(1, k + 1):
        for agg in range(1, k // 2 + 1):
            agg_switch = f'a{(pod - 1) * (k // 2) + agg}'
            for edge in range(1, k // 2 + 1):
                edge_switch = f'e{(pod - 1) * (k // 2) + edge}'
                net.addLink(
                    switches[agg_switch],
                    switches[edge_switch],
                    cls=TCLink,
                    bw=10,
                    delay='20ms'
                )
                info(f"Connected {agg_switch} to {edge_switch} with 10Mbps, 20ms delay\n")

    # Connect Edge to Hosts
    for edge_num in range(1, num_edge + 1):
        edge_switch = f'e{edge_num}'
        for d in range(1, density + 1):
            host_num = (edge_num - 1) * density + d
            host = hosts[f'h{host_num}']
            net.addLink(
                switches[edge_switch],
                host,
                cls=TCLink,
                bw=10,
                delay='10ms'
            )
            info(f"Connected {edge_switch} to {host.name} with 10Mbps, 10ms delay\n")

    # Start the network
    net.start()
    info("Network started.\n")

    # Assign switches to the controller
    for switch in switches.values():
        switch.start([c0])
        info(f"Switch {switch.name} started with controller c0\n")

    # Allow time for the network to stabilize
    time.sleep(5)
    info("Network stabilization complete.\n")

    return net, hosts, switches, dpid_to_switch


def ping_hosts(host1, host2, count=10):
    """
    Ping between two hosts and return the parsed RTT times.

    Args:
        host1 (Host): Source host object.
        host2 (Host): Destination host object.
        count (int): Number of ping packets.

    Returns:
        list: List of RTT times in milliseconds.
    """
    # Perform 5 stabilization pings (unrecorded)
    for _ in range(5):
        host1.cmd(f'ping -c 1 -W 1 {host2.IP()} > /dev/null 2>&1')

    info(f"Pinging {host1.name} to {host2.name} with {count} packets...\n")
    ping_command = f'ping -c {count} {host2.IP()}'
    ping_output = host1.cmd(ping_command)
    info(f"Ping command executed: {ping_command}\n")
    info(f"Raw ping output:\n{ping_output}\n")
    rtts = parse_ping_output(ping_output)

    if rtts:
        info(f"Pings successful. RTTs: {rtts}\n")
    else:
        info("All pings failed or no RTTs parsed.\n")

    return rtts


def parse_ping_output(output):
    """
    Extract RTT times from ping output using regular expressions.

    Args:
        output (str): Raw ping command output.

    Returns:
        list: List of RTT times in milliseconds.
    """
    rtts = []
    # Regular expression to capture RTTs in milliseconds
    pattern = re.compile(r'time=([\d\.]+)\s*ms')
    for line in output.split('\n'):
        match = pattern.search(line)
        if match:
            try:
                rtt = float(match.group(1))
                rtts.append(rtt)
            except ValueError as e:
                info(f"Error converting RTT to float in line: '{line}' - {e}\n")
    if not rtts:
        info("No RTT values parsed from ping output.\n")
    else:
        info(f"Parsed RTTs: {rtts}\n")
    return rtts


def write_results_to_excel(result_file, test_results):
    """
    Write results to the Excel file.

    Args:
        result_file (str): Path to the Excel file.
        test_results (list): List of dictionaries containing test results.
    """
    df_new = pd.DataFrame(test_results)

    try:
        if not os.path.exists(result_file):
            # If the file does not exist, create it and write the data
            with pd.ExcelWriter(result_file, mode='w', engine='openpyxl') as writer:
                df_new.to_excel(writer, sheet_name='Sheet1', index=False)
            info(f"Results successfully written to {result_file}\n")
        else:
            # If the file exists, append the data to the existing sheet
            with pd.ExcelWriter(result_file, mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:
                # Load existing data
                if 'Sheet1' in writer.book.sheetnames:
                    existing_df = pd.read_excel(result_file, sheet_name='Sheet1')
                    df_combined = pd.concat([existing_df, df_new], ignore_index=True)
                else:
                    df_combined = df_new
                # Write combined data
                df_combined.to_excel(writer, sheet_name='Sheet1', index=False)
            info(f"Results successfully appended to {result_file}\n")
    except Exception as e:
        info(f"Error writing results to {result_file}: {e}\n")
        traceback.print_exc()


def get_shortest_path_from_ryu(src, dst):
    """
    Retrieve the shortest path between src and dst switches from the Ryu controller.

    Args:
        src (int): Source switch DPID as integer.
        dst (int): Destination switch DPID as integer.

    Returns:
        list: List of switch DPIDs representing the shortest path.
    """
    try:
        response = requests.post('http://localhost:8080/get_shortest_path', json={'src': src, 'dst': dst}, timeout=5)
        if response.status_code == 200:
            path = response.json()['path']
            info(f"Shortest path retrieved: {path}\n")
            return path
        else:
            info(f"Failed to get path from Ryu: {response.text}\n")
            raise Exception("Failed to get path from Ryu")
    except requests.exceptions.RequestException as e:
        info(f"Error connecting to Ryu controller: {e}\n")
        raise


def measure_recovery_time(net, host1, host2, path_switch_names, dpid_to_switch):
    """
    Take down the first link in the path and measure recovery time.

    Args:
        net (Mininet): The Mininet network object.
        host1 (Host): Source host object.
        host2 (Host): Destination host object.
        path_switch_names (list): List of switch names representing the path.
        dpid_to_switch (dict): Mapping from DPID integers to switch names.

    Returns:
        tuple: Recovery time in milliseconds and list of additional RTTs after recovery.
    """
    if len(path_switch_names) < 2:
        info("Path length is less than 2. Cannot take down a link.\n")
        return None, []

    s1, s2 = path_switch_names[0], path_switch_names[1]
    info(f"Taking down link between {s1} and {s2}\n")
    net.configLinkStatus(s1, s2, 'down')
    time.sleep(1)  # Allow time for the controller to detect the link down event
    start_time = time.perf_counter()

    # Continuously ping to test for recovery
    first_successful_ping = False
    first_ping_time = None
    ping_attempts = 0
    max_ping_attempts = 200  # Increased to allow more retries

    while not first_successful_ping and ping_attempts < max_ping_attempts:
        result = host1.cmd(f'ping -c 1 -W 0.2 {host2.IP()}')
        if '0% packet loss' in result:
            end_time = time.perf_counter()
            first_ping_time = (end_time - start_time) * 1000  # Convert to milliseconds
            info(f"First successful ping after link down in {first_ping_time:.2f} milliseconds.\n")
            first_successful_ping = True
            break
        ping_attempts += 1
        time.sleep(0.05)  # Reduced retry interval

    if not first_successful_ping:
        info("Recovery not achieved within the maximum ping attempts.\n")
        return None, []

    # Introduce a longer delay to allow network stabilization
    stabilization_delay = 1.0  # Increased from 0.5 seconds
    info(f"Waiting {stabilization_delay} seconds for network stabilization...\n")
    time.sleep(stabilization_delay)

    # Retrieve and log the updated shortest path
    src_switch_name = path_switch_names[0]
    dst_switch_name = path_switch_names[-1]

    src_dpid = int(net.get(src_switch_name).dpid, 16)
    dst_dpid = int(net.get(dst_switch_name).dpid, 16)

    updated_shortest_path_dpid = get_shortest_path_from_ryu(src_dpid, dst_dpid)
    info(f"Updated shortest path (DPIDs) after link down: {updated_shortest_path_dpid}\n")

    # Map updated shortest path DPIDs to switch names
    path_switch_names_updated = [dpid_to_switch.get(dpid, None) for dpid in updated_shortest_path_dpid]

    if path_switch_names_updated and all(path_switch_names_updated):
        info(f"Updated shortest path as switch names: {path_switch_names_updated}\n")
    else:
        info("Some switches in the updated path could not be mapped. Skipping path verification.\n")

    # Perform 10 additional pings after recovery
    info("Performing 10 additional pings to verify network stability...\n")
    additional_pings = ping_hosts(host1, host2, count=10)
    info(f"Additional ping results: {additional_pings}\n")

    # Restore the link for the next iteration
    info(f"Restoring link between {s1} and {s2}\n")
    net.configLinkStatus(s1, s2, 'up')
    time.sleep(1)  # Allow time for the controller to re-establish the link

    return first_ping_time, additional_pings


def main():
    setLogLevel('info')

    # Configuration Parameters
    POD = 4
    DENSITY = 2
    RESULT_FILE = '/media/sf_rnad/impt/result/resultfattree.xlsx'  # Ensure this path exists and is writable
    CONTROLLER_IP = '127.0.0.1'
    CONTROLLER_PORT = 6633
    BW_C2A = 10  # Bandwidth Core to Agg
    BW_A2E = 10  # Bandwidth Agg to Edge
    BW_E2H = 10  # Bandwidth Edge to Host

    recovery_times = []

    # Ensure the result directory exists
    result_dir = os.path.dirname(RESULT_FILE)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
        info(f"Created directory {result_dir}\n")

    # Run the test sequence (adjust the range as needed; currently set to 3 for brevity)
    for i in range(1, 3):
        info(f"\nStarting test iteration {i}...\n")
        try:
            net, hosts, switches, dpid_to_switch = create_fattree_topology(k=POD, density=DENSITY)

            # Allow some time for the network to stabilize
            time.sleep(2)

            # Randomly select two distinct hosts for this test
            host1_name, host2_name = random.sample(list(hosts.keys()), 2)
            host1, host2 = hosts[host1_name], hosts[host2_name]

            info(f"Selected hosts: {host1.name} ({host1.IP()}) and {host2.name} ({host2.IP()})\n")

            # Retrieve corresponding switches based on host connections
            # Assuming each host is connected to its own edge switch
            host1_edge_num = (int(host1_name[1:]) - 1) // DENSITY + 1
            host2_edge_num = (int(host2_name[1:]) - 1) // DENSITY + 1
            host1_switch = switches[f'e{host1_edge_num}']
            host2_switch = switches[f'e{host2_edge_num}']

            src_dpid = int(host1_switch.dpid, 16)
            dst_dpid = int(host2_switch.dpid, 16)

            # Retrieve shortest path from Ryu controller
            shortest_path_dpid = get_shortest_path_from_ryu(src_dpid, dst_dpid)
            info(f"Shortest path (DPIDs): {shortest_path_dpid}\n")

            if not shortest_path_dpid:
                info(f"No path found between Switch {src_dpid} and Switch {dst_dpid}\n")
                continue

            # Map DPIDs to switch names
            path_switch_names = [dpid_to_switch.get(dpid, None) for dpid in shortest_path_dpid]
            if any(switch_name is None for switch_name in path_switch_names):
                info("Some switches in the path could not be mapped. Skipping iteration.\n")
                continue
            info(f"Shortest path (Switch names): {path_switch_names}\n")

            # Perform and record 10 pings before taking the link down
            info("Performing 10 pings before taking the link down...\n")
            pre_pings = ping_hosts(host1, host2, count=10)
            test_results = []  # Store results for this iteration

            if pre_pings:
                test_results.append({
                    'Round': f"Iteration {i} - Pre-Link Down Pings",
                    'Min RTT (ms)': min(pre_pings),
                    'Median RTT (ms)': median(pre_pings),
                    'Max RTT (ms)': max(pre_pings),
                    'StdDev RTT (ms)': stdev(pre_pings) if len(pre_pings) > 1 else 0
                })
            else:
                test_results.append({
                    'Round': f"Iteration {i} - Pre-Link Down Pings",
                    'Min RTT (ms)': None,
                    'Median RTT (ms)': None,
                    'Max RTT (ms)': None,
                    'StdDev RTT (ms)': None,
                    'Note': 'Pre-pings failed or no RTTs recorded.'
                })
                info(f"Iteration {i}: Pre-link down pings failed or no RTTs recorded.\n")

            # Measure recovery time and collect additional ping results
            recovery_time, additional_pings = measure_recovery_time(
                net, host1, host2, path_switch_names, dpid_to_switch
            )
            if recovery_time is not None:
                recovery_times.append(recovery_time)
                test_results.append({
                    'Round': f"Iteration {i} - Recovery Time",
                    'Min RTT (ms)': recovery_time,
                    'Median RTT (ms)': None,
                    'Max RTT (ms)': None,
                    'StdDev RTT (ms)': None
                })

                # Record the 10 additional pings
                if additional_pings:
                    test_results.append({
                        'Round': f"Iteration {i} - Additional Pings After Recovery",
                        'Min RTT (ms)': min(additional_pings),
                        'Median RTT (ms)': median(additional_pings),
                        'Max RTT (ms)': max(additional_pings),
                        'StdDev RTT (ms)': stdev(additional_pings) if len(additional_pings) > 1 else 0
                    })
                else:
                    # Log that additional pings were not successful
                    test_results.append({
                        'Round': f"Iteration {i} - Additional Pings After Recovery",
                        'Min RTT (ms)': None,
                        'Median RTT (ms)': None,
                        'Max RTT (ms)': None,
                        'StdDev RTT (ms)': None,
                        'Note': 'Additional pings failed or no RTTs recorded.'
                    })
                    info(f"Iteration {i}: Additional pings failed or no RTTs recorded.\n")

            # Write iteration results to Excel
            write_results_to_excel(RESULT_FILE, test_results)

        except Exception as e:
            info(f"An error occurred during iteration {i}: {e}\n")
            traceback.print_exc()
        finally:
            net.stop()
            info(f"Completed test iteration {i}\n")
        time.sleep(2)

    # Compute and log average recovery time
    if recovery_times:
        avg_recovery_time = mean(recovery_times)
        summary = [{
            'Round': 'Average Link Recovery Time',
            'Min RTT (ms)': avg_recovery_time,
            'Median RTT (ms)': None,
            'Max RTT (ms)': None,
            'StdDev RTT (ms)': None
        }]
        write_results_to_excel(RESULT_FILE, summary)
        info(f"\nAverage recovery time: {avg_recovery_time:.2f} ms\n")
    else:
        info("\nNo recovery times recorded.\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        info("\nSimulation interrupted by user. Exiting...\n")
    except Exception as e:
        info(f"An error occurred: {e}\n")
        traceback.print_exc()
