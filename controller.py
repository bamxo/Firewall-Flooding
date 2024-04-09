# Lab 4 controller skeleton 
#
# Based on of_tutorial by James McCauley
from pox.lib.packet import tcp, udp, arp, icmp
from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
  
  def do_firewall(self, packet, packet_in):
    # The code in here will be executed for every packet
    src_ip = None
    dst_ip = None

    def accept():
        # Write code for an accept function
        msg = of.ofp_flow_mod()
        msg.data = packet_in
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
        #log.info("Packet Accepted - Flow Table Installed on Switches")
        eth_packet = packet.find('ethernet')
        ip_packet = packet.find('ipv4')
        tcp_packet = packet.find('tcp')
        udp_packet = packet.find('udp')
        
        if eth_packet:
            log.info("Packet Accepted - Ethernet: Source MAC: %s, Destination MAC: %s" % (eth_packet.src, eth_packet.dst))
        if ip_packet:
            log.info("Packet Accepted - IPv4: Source IP: %s, Destination IP: %s" % (ip_packet.srcip, ip_packet.dstip))
        if tcp_packet:
            log.info("Packet Accepted - TCP: Source Port: %s, Destination Port: %s" % (tcp_packet.srcport, tcp_packet.dstport))
        if udp_packet:
            log.info("Packet Accepted - UDP: Source Port: %s, Destination Port: %s" % (udp_packet.srcport, udp_packet.dstport))


    def drop():
        # Write code for a drop function
        #log.info("Packet Dropped")
        #log.info("Packet Dropped - Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s" % (packet.src, packet.dst, packet.payload.srcip, packet.payload.dstip))
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
        # Check if the packet contains an IPv4 header
        ip_packet = packet.find('ipv4')
        if ip_packet:
            log.info("Packet Dropped - IPv4: Source IP: %s, Destination IP: %s" % (ip_packet.srcip, ip_packet.dstip))
        
        # Check if the packet contains a TCP header
        tcp_packet = packet.find('tcp')
        if tcp_packet:
            log.info("Packet Dropped - TCP: Source Port: %s, Destination Port: %s" % (tcp_packet.srcport, tcp_packet.dstport))
        
        # Check if the packet contains a UDP header
        udp_packet = packet.find('udp')
        if udp_packet:
            log.info("Packet Dropped - UDP: Source Port: %s, Destination Port: %s" % (udp_packet.srcport, udp_packet.dstport))

    # Write firewall code
                
    # Rule 1: General Connectivity
    if packet.find('arp') or packet.find('icmp'):
        accept()
        return

    ipv4_packet = packet.find('ipv4')
    if ipv4_packet is not None:
        src_ip = ipv4_packet.srcip
        dst_ip = ipv4_packet.dstip
    else:
        # If the packet is not an IPv4 packet, set the source and destination IPs to None
        src_ip = None
        dst_ip = None

    # Rule 2: Web Traffic
    tcp_packet = packet.find('tcp')
    if tcp_packet is not None:
        # Extract the IPv4 packet from the TCP packet
        ipv4_packet = packet.find('ipv4')
        if ipv4_packet is not None:
            # Define the IP addresses for the workstations, personal computers, and web server
            workstation_ips = ["10.0.1.2", "10.0.1.4", "10.0.2.2", "10.0.2.3", "10.0.3.2", "10.0.3.3"]
            web_server_ip = "10.0.100.3"
            
            # Extract source and destination IP addresses from the IPv4 packet
            src_ip = ipv4_packet.srcip
            dst_ip = ipv4_packet.dstip
            
            # Check if the source and destination IP addresses are within the expected ranges
            if (src_ip in workstation_ips and dst_ip == web_server_ip) or \
              (src_ip == web_server_ip and dst_ip in workstation_ips):
                accept()
                return

    # Rule 3: Faculty Access
    if tcp_packet is not None:
        if (src_ip in ["10.0.1.2", "10.0.1.4"] and dst_ip == "10.0.100.2") or \
          (src_ip == "10.0.100.2" and dst_ip in ["10.0.1.2", "10.0.1.4"]):
            accept()
            return

    # Rule 4: IT Management
    if (src_ip in ["10.0.3.2", "10.0.3.3"] and
            dst_ip in ["10.0.1.2", "10.0.1.4", "10.0.2.3", "10.0.3.2", "10.0.3.3"]) or \
      (src_ip in ["10.0.1.2", "10.0.1.4", "10.0.2.3", "10.0.3.2", "10.0.3.3"] and
            dst_ip in ["10.0.3.2", "10.0.3.3"]):
        accept()
        return

    # Rule 5: DNS Traffic
    udp_packet = packet.find('udp')
    if udp_packet is not None:
        if (src_ip in ["10.0.3.2", "10.0.3.3", "10.0.2.3", "10.0.1.4"] and
                dst_ip == "10.0.100.4" and udp_packet.dstport == 53) or \
          (src_ip == "10.0.100.4" and
                dst_ip in ["10.0.3.2", "10.0.3.3", "10.0.2.3", "10.0.1.4"] and udp_packet.dstport == 53):
            accept()
            return
        
    # Rule 7: Printer Access
    if (src_ip.inNetwork("10.0.1.0/24") and dst_ip == "10.0.1.3") or \
      (src_ip == "10.0.1.3" and dst_ip.inNetwork("10.0.1.0/24")):
      accept()
      return

    # Rule 8: Internet Access for guestPC
    if src_ip == "10.0.198.2" or dst_ip == "10.0.198.2":
        # Allow web browsing (HTTP/HTTPS) and DNS queries
        if ((src_ip == "10.0.198.2" and tcp_packet is not None and (tcp_packet.dstport == 80 or tcp_packet.dstport == 443)) or \
            (dst_ip == "10.0.198.2" and tcp_packet is not None and (tcp_packet.srcport == 80 or tcp_packet.srcport == 443))) or \
          ((src_ip == "10.0.198.2" and udp_packet is not None and udp_packet.dstport == 53) or \
            (dst_ip == "10.0.198.2" and udp_packet is not None and udp_packet.srcport == 53)):
            accept()
            return
        else:
            drop()
            return

    # Rule 9: Internet Access for trustedPC
    if src_ip == "10.0.203.2" or dst_ip == "10.0.203.2":
        # Allow web browsing (HTTP/HTTPS), DNS queries, and access to student LAN
        if ((src_ip == "10.0.203.2" and tcp_packet is not None and (tcp_packet.dstport == 80 or tcp_packet.dstport == 443)) or \
            (dst_ip == "10.0.203.2" and tcp_packet is not None and (tcp_packet.srcport == 80 or tcp_packet.srcport == 443))) or \
          ((src_ip == "10.0.203.2" and udp_packet is not None and udp_packet.dstport == 53) or \
            (dst_ip == "10.0.203.2" and udp_packet is not None and udp_packet.srcport == 53)) or \
          (dst_ip.inNetwork("10.0.2.0/24")):
            accept()
            return
        else:
            drop()
            return
        
    # Rule 10: Protect DNS Server from Ping Flood
    icmp_packet = packet.find('icmp')
    if dst_ip == "10.0.100.4" and icmp_packet is not None:
        # Limit the rate of incoming ICMP requests to prevent Ping flood
        if packet_in.in_port not in self.icmp_ports:
            self.icmp_ports[packet_in.in_port] = 0
        self.icmp_ports[packet_in.in_port] += 1
        if self.icmp_ports[packet_in.in_port] > 10:
            drop()
            log.info("Ping Flood Detected - Dropping ICMP packet from port %s" % packet_in.in_port)
        else:
            accept()

    # Rule 6: Default Deny
    drop()



  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the components
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)