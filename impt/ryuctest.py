from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from ryu.topology import event
from ryu.lib import hub
from functools import wraps
import threading
import time
import heapq
from collections import defaultdict
import logging
from flask import Flask, jsonify, request
import re  # For regex in port extraction

# Updates the `recovery_time` attribute of the controller.
def time_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        exec_time = (end_time - start_time) * 1000  # milliseconds
        # Log the execution time
        args[0].recovery_time += exec_time
        args[0].logger.info(f"Execution time of {func.__name__}: {exec_time:.2f} ms")
        return result
    return wrapper

# Ryu manager for topology with Dijkstra-based routing, 
# ARP handling, and link failure recovery.
class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        # Maps dpid to datapath
        self.datapaths = {}
        # Adjacency list: adjacency[dpid][neighbor_dpid] = port_no
        self.adjacency = defaultdict(dict)
        # Host MAC to (dpid, port_no)
        self.hosts = {}
        # Host IP to MAC
        self.arp_table = {}
        # Active flows: (ip_src, ip_dst, eth_type) -> path
        self.active_flows = {}
        # Initialize recovery time accumulator
        self.recovery_time = 0
        # Initialize lock for thread safety
        self.lock = threading.Lock()
        # Initialize Flask app for REST API
        self.app = Flask(__name__)
        # Assign controller to Flask app for access
        self.app.config['controller'] = self
        # Start REST API in separate thread
        hub.spawn(self.run_flask_app)

        # Define REST API routes for getting shortest path and recovery time
        @self.app.route('/get_shortest_path', methods=['POST'])
        def get_shortest_path():
            controller = self.app.config['controller']
            data = request.get_json()
            src = int(data.get('src'))
            dst = int(data.get('dst'))
            with controller.lock:
                path = controller.dijkstra(src, dst)
            if path:
                return jsonify(path=path), 200
            else:
                return jsonify(error="Path not found"), 404

        @self.app.route('/get_recovery_time', methods=['GET'])
        def get_recovery_time():
            controller = self.app.config['controller']
            with controller.lock:
                recovery_time = controller.recovery_time
                controller.recovery_time = 0
            return jsonify(recovery_time=recovery_time), 200

        # Start flow cleanup thread (optional)
        hub.spawn(self.flow_cleanup_thread)

    def run_flask_app(self):
        """
        Runs the Flask REST API.
        """
        self.logger.info("Starting Flask REST API on port 8080")
        self.app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

    def flow_cleanup_thread(self):
        """
        Periodically cleans up inactive or stale flows.
        """
        while True:
            hub.sleep(300)  # Run every 5 minutes
            with self.lock:
                # Implement logic to identify and remove stale flows
                # Example: Remove flows not updated recently
                pass  # Placeholder for actual implementation

    def extract_port_number(self, port_id):
        """
        Extracts the port number from port_id string.
        Assumes port_id is in the format 'ethX' where X is the port number.
        Returns the port number as an integer or None if extraction fails.
        """
        match = re.search(r'\d+', port_id)
        if match:
            return int(match.group())
        else:
            self.logger.error(f"Failed to extract port number from port_id: {port_id}")
            return None

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=3000):
        """
        Adds a flow to the datapath. Uses idle timeout for dynamic management of
        flow table
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    buffer_id=buffer_id, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)
        self.logger.debug(f"FlowMod sent: priority={priority}, match={match}, actions={actions}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handles switch features and installs table-miss flow entry. This ensures that 
        unknown packets are forwarded to the controller for processing.
        """
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Table-miss flow entry installed on Switch {datapath.id}")

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        """
        Handles link additions by updating the adjacency list. Reflects the current topology
        """
        src = ev.link.src
        dst = ev.link.dst
        src_dpid = src.dpid
        dst_dpid = dst.dpid
        src_port = src.port_no
        dst_port = dst.port_no

        # Add both directions to the adjacency list
        self.adjacency[src_dpid][dst_dpid] = src_port
        self.adjacency[dst_dpid][src_dpid] = dst_port

        self.logger.info(f"Link added between Switch {src_dpid} (Port {src_port}) "
                         f"and Switch {dst_dpid} (Port {dst_port})")
        self.logger.debug(f"Updated adjacency list: {dict(self.adjacency)}")

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        """
        Handles link deletions by updating the adjacency list and
        recomputing affected flows.
        """
        src = ev.link.src
        dst = ev.link.dst
        src_dpid = src.dpid
        dst_dpid = dst.dpid

        # Remove both directions from the adjacency list
        if dst_dpid in self.adjacency[src_dpid]:
            del self.adjacency[src_dpid][dst_dpid]
        if src_dpid in self.adjacency[dst_dpid]:
            del self.adjacency[dst_dpid][src_dpid]

        self.logger.info(f"Link removed between Switch {src_dpid} and Switch {dst_dpid}")
        self.logger.debug(f"Updated adjacency list after link removal: {dict(self.adjacency)}")

        # Trigger path recomputation for affected flows
        self.handle_link_failure(src_dpid, dst_dpid)

    def dijkstra(self, src, dst):
        """
        Custom implementation of Dijkstra's algorithm to find the shortest path
        from src to dst based on link costs.
        """
        queue = []
        heapq.heappush(queue, (0, src, [src]))  # (cost, current_node, path)

        visited = set()

        while queue:
            cost, current, path = heapq.heappop(queue)

            if current == dst:
                return path

            if current in visited:
                continue
            visited.add(current)

            for neighbor in self.adjacency[current]:
                if neighbor not in visited:
                    # Assign uniform cost; modify if different link costs are needed
                    new_cost = cost + 1
                    heapq.heappush(queue, (new_cost, neighbor, path + [neighbor]))

        return None  # No path found

    @time_function
    def install_path(self, src_dpid, src_port, dst_dpid, dst_port, ip_src, ip_dst, eth_type=0x0800):
        """
        Installs a flow from src to dst using the computed path.
        Returns the path if successful, else None.
        """
        path = self.dijkstra(src_dpid, dst_dpid)
        if not path:
            self.logger.error(f"No path found from Switch {src_dpid} to Switch {dst_dpid}")
            return None

        self.logger.info(f"Installing path: {path} for flow {ip_src} -> {ip_dst} (eth_type={hex(eth_type)})")

        # Install flows along the path
        for i in range(len(path)):
            current_switch = path[i]
            datapath = self.datapaths.get(current_switch)
            if not datapath:
                self.logger.error(f"Datapath for Switch {current_switch} not found.")
                continue
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            if i == 0:
                # Source switch: in_port is src_port, out_port is to next switch
                in_port = src_port
                out_port = self.adjacency[current_switch][path[i + 1]]
            elif i == len(path) - 1:
                # Destination switch: in_port is from previous switch, out_port is dst_port
                in_port = self.adjacency[current_switch][path[i - 1]]
                out_port = dst_port
            else:
                # Intermediate switch: in_port is from previous, out_port is to next
                in_port = self.adjacency[current_switch][path[i - 1]]
                out_port = self.adjacency[current_switch][path[i + 1]]

            if eth_type == 0x0800:
                # IPv4
                match = parser.OFPMatch(
                    eth_type=eth_type,  # IPv4
                    ipv4_src=ip_src,
                    ipv4_dst=ip_dst,
                    in_port=in_port
                )
            elif eth_type == 0x0806:
                # ARP
                match = parser.OFPMatch(
                    eth_type=eth_type,  # ARP
                    arp_spa=ip_src,      # ARP Sender Protocol Address
                    arp_tpa=ip_dst,      # ARP Target Protocol Address
                    in_port=in_port
                )
            else:
                # Unsupported eth_type
                self.logger.error(f"Unsupported eth_type: {eth_type}")
                continue

            actions = [parser.OFPActionOutput(out_port)]
            priority = 1000  # Set appropriate priority

            self.add_flow(datapath, priority, match, actions)
            self.logger.debug(f"Flow installed on Switch {current_switch}: "
                              f"in_port={in_port} -> out_port={out_port}, eth_type={hex(eth_type)}")

        return path

    def install_path_bidirectional(self, src_dpid, src_port, dst_dpid, dst_port, ip_src, ip_dst, eth_type=0x0800):
        """
        Installs flows in both directions between src and dst for the given IPs and eth_type.
        Bidirectional for communication
        """
        self.logger.debug(f"Installing bidirectional flows for {ip_src} <-> {ip_dst} (eth_type={hex(eth_type)})")
        # Install forward path
        path_fwd = self.install_path(src_dpid, src_port, dst_dpid, dst_port, ip_src, ip_dst, eth_type)
        if path_fwd:
            self.active_flows[(ip_src, ip_dst, eth_type)] = path_fwd
            self.logger.info(f"Forward path for {ip_src} -> {ip_dst} stored in active_flows.")

        # Install reverse path
        path_rev = self.install_path(dst_dpid, dst_port, src_dpid, src_port, ip_dst, ip_src, eth_type)
        if path_rev:
            self.active_flows[(ip_dst, ip_src, eth_type)] = path_rev
            self.logger.info(f"Reverse path for {ip_dst} -> {ip_src} stored in active_flows.")

        # Log current active flows
        self.log_active_flows()

    def handle_link_failure(self, failed_src, failed_dst):
        """
        Handles link failures by identifying affected flows and reinstalling paths.
        """
        affected_flows = []

        # Identify affected flows
        for (ip_src, ip_dst, eth_type), path in list(self.active_flows.items()):
            if not path:
                continue
            # Check if the failed link is in the current path
            for i in range(len(path) - 1):
                if (path[i] == failed_src and path[i + 1] == failed_dst) or \
                   (path[i] == failed_dst and path[i + 1] == failed_src):
                    affected_flows.append((ip_src, ip_dst, eth_type))
                    del self.active_flows[(ip_src, ip_dst, eth_type)]
                    break

        self.logger.info(f"Affected flows due to link failure between "
                         f"Switch {failed_src} and Switch {failed_dst}: {affected_flows}")

        # Recompute and reinstall paths for affected flows
        for (ip_src, ip_dst, eth_type) in affected_flows:
            src_host = self.get_host_info(ip_src)
            dst_host = self.get_host_info(ip_dst)
            if src_host and dst_host:
                src_dpid, src_port = src_host
                dst_dpid, dst_port = dst_host
                self.install_path_bidirectional(src_dpid, src_port, dst_dpid, dst_port,
                                                ip_src, ip_dst, eth_type)
            else:
                self.logger.error(f"Host information missing for IPs: {ip_src}, {ip_dst}")

    def get_host_info(self, ip):
        """
        Retrieves host information (dpid and port_no) based on IP.
        Assumes that ARP table is populated.
        """
        mac = self.arp_table.get(ip)
        if not mac:
            self.logger.error(f"MAC address for IP {ip} not found in ARP table.")
            return None
        host_info = self.hosts.get(mac)
        if not host_info:
            self.logger.error(f"Host with MAC {mac} not found in hosts mapping.")
            return None
        return host_info  # (dpid, port_no)

    def log_active_flows(self):
        """
        Logs all active flows and their paths for debugging purposes.
        """
        if not self.active_flows:
            self.logger.info("No active flows to display.")
            return

        self.logger.info("Current Active Flows and Their Paths:")
        for (ip_src, ip_dst, eth_type), path in self.active_flows.items():
            self.logger.info(f"Flow {ip_src} -> {ip_dst} (eth_type={hex(eth_type)}): Path {path}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles incoming packets sent to controllers and installs flows accordingly.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Optionally handle LLDP packets if needed
            # self.handle_lldp(datapath, in_port, pkt)
            return  # Ignore LLDP packets

        src_mac = eth.src
        dst_mac = eth.dst

        # Learn host locations
        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)
            self.logger.info(f"Host {src_mac} is attached to Switch {dpid} Port {in_port}")

        if arp_pkt:
            self.handle_arp(datapath, in_port, src_mac, dst_mac, arp_pkt, msg.data)  # Pass msg.data
        elif ipv4_pkt:
            self.handle_ipv4(datapath, in_port, src_mac, dst_mac, ipv4_pkt)


    def handle_ipv4(self, datapath, in_port, src_mac, dst_mac, ipv4_pkt):
        """
        Handles IPv4 packets by installing flows after identifying src and dst hosts
        """
        ip_src = ipv4_pkt.src
        ip_dst = ipv4_pkt.dst
        self.logger.info(f"IPv4 packet received: {ip_src} -> {ip_dst}")

        src_host = self.hosts.get(src_mac)
        dst_host = self.hosts.get(dst_mac)

        if src_host and dst_host:
            src_dpid, src_port = src_host
            dst_dpid, dst_port = dst_host
            self.install_path_bidirectional(src_dpid, src_port, dst_dpid, dst_port,
                                            ip_src, ip_dst, eth_type=0x0800)
        else:
            self.logger.error(f"Host information missing for MACs: src_mac={src_mac}, dst_mac={dst_mac}")

    def handle_arp(self, datapath, in_port, src_mac, dst_mac, arp_pkt, data):
        """
        Handles ARP packets by updating ARP tables and responding to ARP requests if possible.
        Processes ARP packets, updates the ARP table, responds to ARP requests, 
        or floods ARP requests when necessary.
        Tracks IP-MAC mappings
        
        Args:
            datapath (RyuDatapath): The datapath object representing the switch.
            in_port (int): The port number where the packet was received.
            src_mac (str): Source MAC address.
            dst_mac (str): Destination MAC address.
            arp_pkt (arp.arp): The ARP packet parsed from the incoming packet.
            data (bytes): The raw packet data.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        opcode = arp_pkt.opcode
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        src_mac_addr = arp_pkt.src_mac
        dst_mac_addr = arp_pkt.dst_mac

        self.logger.info(
            f"ARP Packet: opcode={opcode}, src_ip={src_ip}, src_mac={src_mac_addr}, "
            f"dst_ip={dst_ip}, dst_mac={dst_mac_addr}"
        )

        # Update ARP table with sender's IP and MAC
        self.arp_table[src_ip] = src_mac_addr
        self.logger.debug(f"Updated ARP table: {src_ip} -> {src_mac_addr}")

        if opcode == arp.ARP_REQUEST:
            self.logger.info(f"Handling ARP Request: Who has {dst_ip}? Tell {src_ip}")

            # Check if the controller knows the target IP's MAC address
            target_mac = self.arp_table.get(dst_ip)
            if target_mac:
                self.logger.info(f"Known MAC for {dst_ip} is {target_mac}. Sending ARP Reply.")

                # Retrieve the switch and port where the target host is connected
                target_host = self.hosts.get(target_mac)
                if target_host:
                    target_dpid, target_port = target_host
                    target_datapath = self.datapaths.get(target_dpid)

                    if target_datapath:
                        # Construct Ethernet and ARP reply packets
                        ether = ethernet.ethernet(
                            dst=src_mac,
                            src=target_mac,
                            ethertype=ether_types.ETH_TYPE_ARP
                        )
                        arp_reply = arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=target_mac,
                            src_ip=dst_ip,
                            dst_mac=src_mac,
                            dst_ip=src_ip
                        )
                        pkt = packet.Packet()
                        pkt.add_protocol(ether)
                        pkt.add_protocol(arp_reply)
                        pkt.serialize()

                        # Create actions to send the ARP reply back to the requester
                        actions = [parser.OFPActionOutput(in_port)]

                        # Create the PacketOut message with serialized packet data
                        out = parser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=ofproto.OFP_NO_BUFFER,
                            in_port=in_port,
                            actions=actions,
                            data=pkt.data  # Correctly pass serialized data
                        )

                        # Send the message
                        try:
                            datapath.send_msg(out)
                            self.logger.info(f"PacketOut sent successfully on datapath {datapath.id}")
                        except Exception as e:
                            self.logger.error(f"Failed to send PacketOut: {e}")

                        self.logger.debug(f"Sent ARP Reply to {src_mac} on Switch {target_dpid} Port {target_port}")
                    else:
                        self.logger.error(f"Datapath for Switch {target_dpid} not found.")
                else:
                    self.logger.error(f"Host information for MAC {target_mac} not found.")
            else:
                self.logger.info(f"MAC for {dst_ip} unknown. Flooding ARP request.")

                # Flood the ARP request to all ports except the incoming port
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=data  # Correctly pass the original packet data
                )
                try:
                    datapath.send_msg(out)
                    self.logger.debug(f"Flooded ARP Request on Switch {datapath.id}")
                except Exception as e:
                    self.logger.error(f"Failed to flood ARP Request: {e}")

        elif opcode == arp.ARP_REPLY:
            self.logger.info(f"Handling ARP Reply: {src_ip} is at {src_mac}")

            # Update ARP table with receiver's IP and MAC if not already done
            if dst_ip not in self.arp_table:
                self.arp_table[dst_ip] = dst_mac_addr
                self.logger.debug(f"Updated ARP table: {dst_ip} -> {dst_mac_addr}")

            # Optionally, install flows based on the ARP reply
            # For example, establish bidirectional flows between src and dst
            src_host = self.hosts.get(src_mac)
            dst_host = self.hosts.get(dst_mac)

            if src_host and dst_host:
                src_dpid, src_port = src_host
                dst_dpid, dst_port = dst_host
                self.install_path_bidirectional(
                    src_dpid, src_port,
                    dst_dpid, dst_port,
                    src_ip, dst_ip,
                    eth_type=ether_types.ETH_TYPE_ARP
                )
                self.logger.info(f"Installed bidirectional flows for ARP Reply between {src_ip} and {dst_ip}")
            else:
                self.logger.error(f"Host information missing for ARP Reply: src_mac={src_mac}, dst_mac={dst_mac}")

        else:
            self.logger.warning(f"Unhandled ARP opcode: {opcode}")
