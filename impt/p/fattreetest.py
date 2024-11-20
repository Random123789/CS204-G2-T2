import os
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time


def create_fattree_topology(k=4, density=2):
    """
    Create a Fat-Tree topology with specified parameters.

    Args:
        k (int): Parameter defining the size of the Fat-Tree.
        density (int): Number of hosts per edge switch.

    Returns:
        net (Mininet): The initialized Mininet network.
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

    return net


def main():
    setLogLevel('info')

    # Configuration Parameters
    POD = 4
    DENSITY = 2

    try:
        net = create_fattree_topology(k=POD, density=DENSITY)
        info("Starting CLI for manual interaction...\n")
        CLI(net)  # Start CLI for manual control
    except Exception as e:
        info(f"An error occurred: {e}\n")
    finally:
        net.stop()
        info("Network stopped. Exiting...\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        info("\nSimulation interrupted by user. Exiting...\n")
