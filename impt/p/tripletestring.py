import os
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time


def create_sdn_topology():
    """Create an SDN topology with consistent propagation delays."""
    # Initialize Mininet with TCLink to allow link configuration
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Add switches for segment A
    sa_switches = {
        f'sa{i}': net.addSwitch(
            f'sa{i}', 
            cls=OVSKernelSwitch, 
            protocols='OpenFlow13', 
            stp=False
        ) for i in range(1, 21)
    }

    # Define and add hosts
    hosts = {
        f'ha{i}': net.addHost(
            f'ha{i}', 
            ip=f'10.0.{(i - 1) // 5}.{(i - 1) % 5 + 1}'
        ) for i in range(1, 21)
    }

    # Define fixed delays
    FIXED_HOST_SWITCH_DELAY = '10ms'    # Fixed delay for host-switch links
    FIXED_SWITCH_SWITCH_DELAY = '20ms'  # Fixed delay for switch-switch links

    # Connect each host to its respective switch with consistent delay
    for i in range(1, 21):
        net.addLink(
            hosts[f'ha{i}'], 
            sa_switches[f'sa{i}'], 
            cls=TCLink, 
            delay=FIXED_HOST_SWITCH_DELAY
        )
        info(
            f"Added link between {hosts[f'ha{i}'].name} "
            f"and {sa_switches[f'sa{i}'].name} with delay {FIXED_HOST_SWITCH_DELAY}\n"
        )

    # Create ring topology among switches with consistent delay
    for i in range(1, 20):
        net.addLink(
            sa_switches[f'sa{i}'], 
            sa_switches[f'sa{i+1}'], 
            cls=TCLink, 
            delay=FIXED_SWITCH_SWITCH_DELAY
        )
        info(
            f"Added link between {sa_switches[f'sa{i}'].name} "
            f"and {sa_switches[f'sa{i+1}'].name} with delay {FIXED_SWITCH_SWITCH_DELAY}\n"
        )
    
    # Complete the ring with consistent delay
    net.addLink(
        sa_switches['sa20'], 
        sa_switches['sa1'], 
        cls=TCLink, 
        delay=FIXED_SWITCH_SWITCH_DELAY
    )
    info(
        f"Added link between {sa_switches['sa20'].name} "
        f"and {sa_switches['sa1'].name} with delay {FIXED_SWITCH_SWITCH_DELAY}\n"
    )

    # Start the network
    net.start()
    info("Network started.\n")

    # Assign switches to the controller
    for switch in sa_switches.values():
        switch.start([c0])
        info(f"Switch {switch.name} started with controller c0\n")

    # Allow time for the network to stabilize
    time.sleep(5)
    info("Network stabilization complete.\n")
    
    return net


def main():
    setLogLevel('info')
    try:
        # Create the topology
        net = create_sdn_topology()
        info("Starting CLI for manual interaction...\n")
        CLI(net)  # Start CLI for manual control
    except Exception as e:
        info(f"An error occurred: {e}\n")
    finally:
        net.stop()
        info("Network stopped. Exiting...\n")


if __name__ == '__main__':
    main()