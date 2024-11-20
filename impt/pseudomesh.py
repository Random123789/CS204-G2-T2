import os
import requests
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
import time, random
from statistics import mean, median, stdev
from mininet.log import setLogLevel, info
import pandas as pd
import traceback
import re


def create_sdn_topology():
    """Create an SDN topology with consistent propagation delays."""
    # Initialize Mininet with TCLink to allow link configuration
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Add switches
    sa_switches = {f'sa{i}': net.addSwitch(f'sa{i}', cls=OVSKernelSwitch, protocols='OpenFlow13', stp=False) for i in range(1, 21)}

    # Define and add hosts only to switches sa2 to sa20
    hosts = {f'ha{i}': net.addHost(f'ha{i}', ip=f'10.0.{i-1}.1') for i in range(2, 21)}
    
    # Define fixed delays
    FIXED_HOST_SWITCH_DELAY = '10ms'    # Fixed delay for host-switch links
    FIXED_SWITCH_SWITCH_DELAY = '20ms'  # Fixed delay for switch-switch links

    # Connect each host to its respective switch with consistent delay
    for i in range(2, 21):
        net.addLink(hosts[f'ha{i}'], sa_switches[f'sa{i}'], cls=TCLink, delay=FIXED_HOST_SWITCH_DELAY)
        info(f"Added link between {hosts[f'ha{i}'].name} and {sa_switches[f'sa{i}'].name} with delay {FIXED_HOST_SWITCH_DELAY}\n")

    # Connect each of the other switches to the central switch (sa1) with consistent delay
    for i in range(2, 21):
        net.addLink(sa_switches['sa1'], sa_switches[f'sa{i}'], cls=TCLink, delay=FIXED_SWITCH_SWITCH_DELAY)
        info(f"Added link between sa1 and {sa_switches[f'sa{i}'].name} with delay {FIXED_SWITCH_SWITCH_DELAY}\n")

    # Create a ring topology among the switches excluding the central switch with consistent delay
    for i in range(2, 20):
        net.addLink(sa_switches[f'sa{i}'], sa_switches[f'sa{i+1}'], cls=TCLink, delay=FIXED_SWITCH_SWITCH_DELAY)
        info(f"Added link between {sa_switches[f'sa{i}'].name} and {sa_switches[f'sa{i+1}'].name} with delay {FIXED_SWITCH_SWITCH_DELAY}\n")
    
    # Complete the ring with consistent delay
    net.addLink(sa_switches['sa20'], sa_switches['sa2'], cls=TCLink, delay=FIXED_SWITCH_SWITCH_DELAY)
    info(f"Added link between sa20 and sa2 with delay {FIXED_SWITCH_SWITCH_DELAY}\n")

    net.start()

    # Assign controllers to specific switches
    for switch in sa_switches.values():
        switch.start([c0])
        info(f"Switch {switch.name} started with controller c0\n")

    # Allow time for the network to stabilize
    time.sleep(5)
    info("Network stabilization complete.\n")
    
    return net, hosts


def ping_hosts(host1, host2, count=10):
    """Ping between two hosts and return the parsed RTT times."""
    # Perform 5 stabilization pings (unrecorded)
    for _ in range(5):
        host1.cmd('ping -c 1 -W 1 %s > /dev/null 2>&1' % host2.IP())
    
    info(f"Pinging {host1.name} to {host2.name} with {count} packets...\n")
    ping_command = 'ping -c {} {}'.format(count, host2.IP())
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
    """Extract RTT times from ping output using regular expressions."""
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
    """Write results to the Excel file."""
    df_new = pd.DataFrame(test_results)
    
    try:
        if not os.path.exists(result_file):
            # If the file does not exist, create it and write the data
            with pd.ExcelWriter(result_file, mode='w', engine='openpyxl') as writer:
                df_new.to_excel(writer, sheet_name='Sheet1', index=False)
            info(f"Results successfully written to {result_file}\n")
        else:
            # If the file exists, append the data to the existing sheet
            with pd.ExcelWriter(result_file, mode='a', engine='openpyxl', if_sheet_exists='replace') as writer:
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
    """Retrieve the shortest path between src and dst switches from the Ryu controller."""
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


def measure_recovery_time(net, host1, host2, path):
    """Take down the first link in the path and measure recovery time."""
    s1, s2 = path[0], path[1]
    info(f"Taking down link between sa{s1} and sa{s2}\n")
    net.configLinkStatus(f'sa{s1}', f'sa{s2}', 'down')
    time.sleep(1)  # Allow time for the controller to detect the link down event
    start_time = time.perf_counter()

    # Continuously ping to test for recovery
    first_successful_ping = False
    first_ping_time = None
    ping_attempts = 0
    max_ping_attempts = 200  # Increased to allow more retries

    while not first_successful_ping and ping_attempts < max_ping_attempts:
        result = host1.cmd('ping -c 1 -W 0.2 %s' % host2.IP())  # Reduced timeout
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

    # Optionally, retrieve and log the updated shortest path
    updated_shortest_path = get_shortest_path_from_ryu(int(host1.name[2:]), int(host2.name[2:]))
    info(f"Updated shortest path after link down: {updated_shortest_path}\n")

    # Perform 10 additional pings after recovery
    info("Performing 10 additional pings to verify network stability...\n")
    additional_pings = ping_hosts(host1, host2, count=10)
    info(f"Additional ping results: {additional_pings}\n")

    return first_ping_time, additional_pings


def main():
    setLogLevel('info')
    
    result_file = '/media/sf_rnad/impt/result/resultmesh.xlsx'
    recovery_times = []

    # Ensure the result directory exists
    result_dir = os.path.dirname(result_file)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
        info(f"Created directory {result_dir}\n")

    # Run the test sequence 10 times (adjust as needed)
    for i in range(1, 4):
        info(f"\nStarting test iteration {i}...\n")
        net, hosts = create_sdn_topology()
        test_results = []  # Store results for this iteration

        try:
            # Randomly select two distinct hosts for this test
            host1_name, host2_name = random.sample(list(hosts.keys()), 2)
            host1, host2 = hosts[host1_name], hosts[host2_name]

            info(f"Selected hosts: {host1.name} ({host1.IP()}) and {host2.name} ({host2.IP()})\n")

            # Retrieve shortest path from Ryu controller
            src_switch_id = int(host1_name[2:])
            dst_switch_id = int(host2_name[2:])
            shortest_path = get_shortest_path_from_ryu(src_switch_id, dst_switch_id)
            info(f"Shortest path: {shortest_path}\n")

            # Perform and record 10 pings before taking the link down
            info("Performing 10 pings before taking the link down...\n")
            pre_pings = ping_hosts(host1, host2, count=10)
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
            recovery_time, additional_pings = measure_recovery_time(net, host1, host2, shortest_path)
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
            write_results_to_excel(result_file, test_results)

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
        write_results_to_excel(result_file, summary)
        info(f"\nAverage recovery time: {avg_recovery_time:.2f} ms\n")
    else:
        info("\nNo recovery times recorded.\n")


if __name__ == '__main__':
    main()
