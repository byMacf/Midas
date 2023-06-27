import socket
import struct

from dataclasses import dataclass
from datetime import datetime
from utils.log import log

# Reference docs
# https://docs.microsoft.com/en-us/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics

FORMAT_STRING = (
    "!" # Specifies network byte order
    "s" # OP: 1 byte
    "s" # HTYPE: 1 byte
    "s" # HLEN: 1 byte
    "s" # HOPS: 1 byte
    "4s" # XID: 4 bytes
    "2s" # SECS: 2 bytes
    "2s" # FLAGS: 2 bytes
    "4s" # CIADDR: 4 bytes
    "4s" # YIADDR: 4 bytes
    "4s" # SIADDR: 4 bytes
    "4s" # GIADDR: 4 bytes
    "6s" # CHADDR: 6 bytes
    "10s" # CHADDR: 10 bytes
    "192s" # OVERFLOW: 192 bytes
     "4s" # MAGICCOOKIE: 4 bytes
) # 240 bytes total

OPTION_DESCRIPTIONS = {
    1: 'Subnet Mask',
    3: 'Default Gateway',
    12: 'Hostname',
    43: 'Vendor Specific Information',
    50: 'Requested IP Address',
    51: 'IP Address Lease Time',
    53: 'DHCP Message Type',
    54: 'DHCP Server IP Address',
    55: 'Parameter Request List',
    57: 'DHCP Maximum Message Size',
    60: 'Class Identifier',
    61: 'Client Identifier',
    67: 'Boot File Name',
    150: 'TFTP Server IP Address',
}

@dataclass()
class DHCPPacket:
    # Based on DHCP Discovery packet header from: https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
    # Packet header field byte sizing: https://support.huawei.com/enterprise/en/doc/EDOC1100058931/25cd2dfc/dhcp-messages
    # DHCP packet types: https://www.omnisecu.com/tcpip/dhcp-dynamic-host-configuration-protocol-message-options.php

    OP: bytes
    HTYPE: bytes
    HLEN: bytes
    HOPS: bytes
    XID: bytes
    SECS: bytes
    FLAGS: bytes
    CIADDR: bytes # Client IP address
    YIADDR: bytes # DHCP Server IP address
    SIADDR: bytes # Server IP address
    GIADDR: bytes # Gateway IP address
    CHADDR: bytes # Client hardware address
    CHADDR_PADDING: bytes
    OVERFLOW: bytes # Overflow space for BOOTP legacy
    MCOOKIE: bytes
    OPTIONS: bytes
    END: bytes = bytes([0xFF])

class Packet():
    @staticmethod
    def construct_tlv(_type, value):
        '''
            Summary:
            Constructs a DHCP TLV - Type | Length | Value.

            Takes:
            _type: typically the DHCP option number
            value: value of the TLV, can be text or integer

            Returns:
            A bytes object TLV
        '''
        if isinstance(value, str):
            value = str.encode(value)
        return bytes([_type, len(value)]) + value

    @staticmethod
    def construct_junos_suboptions(config_filename):
        '''
            Summary:
            Constructs Junos specific suboptions required for Zero Touch Provisioning to work.

            0: firmware file
            1: configuration file
            3: transfer mode

            Additional options are available, see: 
            https://www.juniper.net/documentation/us/en/software/junos/junos-install-upgrade/topics/topic-map/zero-touch-provision.html#id-zero-touch-provisioning-using-dhcp-options

            Takes:
            config_filename: filename and path of the configuration file to be retrieved and applied to the client

            Returns:
            A bytes object consisting of multiple TLVs
        '''
        return Packet.construct_tlv(
            _type=43,
            value=b''.join(
                [
                    #Packet.construct_tlv(0, '/path/to/junosimage.tgz'), # Image filename and path, for upgrading firmware
                    Packet.construct_tlv(1, config_filename), # Configuration filename and path
                    Packet.construct_tlv(3, 'tftp'), # Transfer mode
                ]
            )
        )

    @staticmethod
    def construct_reply_packet(reference_packet, _type, source_ip, topology):
        '''
            Summary:
            Constructs a DHCP packet of type Offer or Ack, modelled from a received packet with some options changed/added.
            Ack packets are the exact same as Offer packets, just with the packet type TLV adjusted.
            Different options are changed/added based on client operating system extracted from the networkx Graph object.

            Takes:
            reference_packet: received DHCP packet to model the reply packet from
            _type: type of packet to construct, Offer or Ack
            source_ip: IP address that the DHCP packet was received from
            topology: networkx Graph object detailing the network topology

            Returns:
            DHCP packet of type Offer or Ack
        '''
        packet_data = struct.unpack(FORMAT_STRING, reference_packet[:240])
        reply_packet_object = DHCPPacket(*packet_data, OPTIONS=reference_packet[240:len(reference_packet)])

        giaddr, yiaddr = Packet.process_giaddr(source_ip)
        client_device_name, client_device_os = topology.get_client_calling_for_ip(source_ip, _type)

        reply_packet_object.OP = bytes([0x02])
        reply_packet_object.YIADDR = bytes([yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]]) # Client IP
        reply_packet_object.SIADDR = bytes([172, 16, 0, 200]) # Server IP: 172.16.0.200

        if _type == 'offer': 
            packet_type = bytes([53, 1, 2]) # DHCP offer packet
        elif _type == 'ack': 
            packet_type = bytes([53, 1, 5]) # DHCP ack packet

        if client_device_os == 'junos':
            reply_packet_object.OPTIONS = b"".join(
                [
                    packet_type,
                    bytes([54, 4, 172, 16, 0, 200]), # Server identifier: 172.16.0.200
                    bytes([51, 4, 0x00, 0x01, 0x51, 0x80]), # Lease time: 86400
                    bytes([1, 4, 255, 255, 255, 254]), # Subnet mask: 255.255.255.254
                    bytes([3, 4, giaddr[0], giaddr[1], giaddr[2], giaddr[3]]), # Default gateway
                    bytes([150, 4, 172, 16, 0, 200]), # TFTP server: 172.16.0.200
                    Packet.construct_junos_suboptions(f'/configs/{client_device_name}.conf'), # Juniper specific suboptions
                ]
            )
        elif client_device_os == 'cisco_ios':
            reply_packet_object.OPTIONS = b"".join(
                [
                    packet_type,
                    bytes([54, 4, 172, 16, 0, 200]), # Server identifier: 172.16.0.200
                    bytes([51, 4, 0x00, 0x01, 0x51, 0x80]), # Lease time: 86400
                    bytes([1, 4, 255, 255, 255, 254]), # Subnet mask: 255.255.255.254
                    bytes([3, 4, giaddr[0], giaddr[1], giaddr[2], giaddr[3]]), # Default gateway
                    bytes([150, 4, 172, 16, 0, 200]), # TFTP server: 172.16.0.200
                    Packet.construct_tlv(67, f'/configs/{client_device_name}.conf'), # Cisco specific bootfile
                ]
            )

        reply_packet_list = []

        for field, byte_value in reply_packet_object.__dict__.items():
            reply_packet_list.append(byte_value)

        reply_packet = b''.join(value for value in reply_packet_list)

        return reply_packet
    
    @staticmethod
    def examine_packet(raw_packet):
        '''
            Summary:
            Examines a DHCP packet and splits it into packet data and DHCP options.
            It's expected that DHCP packet length after 240 will be DHCP options.

            Takes:
            raw_packet: raw DHCP packet to examine

            Returns:
            packet: DHCP packet data minus options
            options: DHCP packet options
            options_descriptions: DHCP packet options descriptions
        '''
        packet_data = struct.unpack(FORMAT_STRING, raw_packet[:240])
        packet = DHCPPacket(*packet_data, OPTIONS=raw_packet[240:len(raw_packet)])

        options, options_descriptions = Packet.extract_options(packet.OPTIONS)

        return packet, options, options_descriptions

    @staticmethod
    def extract_options(packet_data):
        '''
            Summary:
            Extracts DHCP options from a given raw DHCP packet.

            Takes:
            packet_data: DHCP packet as raw bytes

            Returns:
            option_dict: dictionairy of DHCP options extracted from a packet
            option_description_dict: dictionairy of DHCP option descriptions that were found in a packet
        '''
        option_dict = {}
        option_description_dict = {}

        index = 0
        while index < len(packet_data):
            option_number = packet_data[index]
            if option_number == 255:
                break
            option_length = packet_data[index + 1]
            option_value, option_description = Packet.make_human_readable(option_number, packet_data[index + 2 : index + 2 + option_length])

            option_dict[option_number] = option_value
            option_description_dict[option_number] = option_description
            index += 2 + option_length


        return option_dict, option_description_dict

    @staticmethod
    def make_human_readable(option_number, raw_value):
        '''
            Summary:
            Takes a raw DHCP option and makes it human readable.

            DHCP options:
            https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml

            Takes:
            option_number: DHCP option number
            raw_value: raw bytes value received with the option number

            Returns:
            option_value: human readable value of the option number
            option_description: description of the option
        '''
        if option_number in [1, 3, 50, 54, 150]:
            octets = list(raw_value)
            option_value = f'{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}'
        elif option_number in [50, 55]:
            option_value = list(raw_value)
        elif option_number == 53:
            option_value = list(raw_value)[0]
        elif option_number in [60, 12, 61, 67, 43]:
            option_value = raw_value.decode()
        elif option_number in [51, 57]:
            option_value = int.from_bytes(raw_value, byteorder='big')
        else: 
            option_value = raw_value

        if option_number in OPTION_DESCRIPTIONS:
            option_description = OPTION_DESCRIPTIONS[option_number]
        else:
            option_description = 'Unknown'

        return option_value, option_description

    @staticmethod
    def process_giaddr(giaddr):
        '''
            Summary:
            Calculates IP address to offer the client and turns string giaddr into a list of 4 integers.

            Takes:
            giaddr: gateway or relay IP that the DHCP packet was received from (string)

            Returns:
            giaddr: gateway or relay IP that the DHCP packet was received from (list of 4 integers)
            yiaddr: IP to offer the client (list of 4 integers)
        '''
        octets = giaddr.split('.')
        last_octet = int(octets[3])
        giaddr = [int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3])]

        if last_octet % 2 == 0:
            yiaddr = [int(octets[0]), int(octets[1]), int(octets[2]), int(last_octet + 1)]
        else:
            yiaddr = [int(octets[0]), int(octets[1]), int(octets[2]), int(last_octet - 1)]

        return giaddr, yiaddr

class DHCPServer():
    MAX_BYTES = 1024
    SERVER_IP = '172.16.0.200'
    PORT = 67

    def create_socket(self):
        '''
            Summary:
            Creates a socket to allow the DHCP server to send and receive data to/from.

            Socket characteristics:
            AF_INET: type of socket, address format (host, port)
            SOCK_DGRAM: socket protocol, UDP
            SOL_SOCKET (socket options):
            SO_REUSEADDR: socket address and port can be reused
            SO_BROADCAST: datagrams can be broadcast from this socket

            Socket bound to:
            SERVER_IP
            PORT
        '''
        _socket=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
        _socket.bind((self.SERVER_IP, self.PORT))

        return _socket

    def run(self, topology):
        '''
            Summary:
            Runs the DHCP server allowing packets to be sent and received through the created socket.

            Takes:
            topology: networkx Graph object detailing the network topology
        '''
        log('DHCP server is starting...', 'info')
        socket = self.create_socket()

        while True:
            try:
                log('Waiting for DHCP packets...', 'info')
                received_packet, (source_address, source_port) = socket.recvfrom(self.MAX_BYTES)
                log(f'DHCP packet received from IP {source_address} on port {source_port}', 'info')
                packet_data, packet_options, option_descriptions = Packet.examine_packet(received_packet)
                log(f'Received packet options:', 'info')
                for option_number, option_value in packet_options.items():
                    log(f'{option_number} [{option_descriptions[option_number]}]: {option_value}', 'info')

                if packet_options[53] == 1:
                    log('Received DHCP discover packet', 'info')
                    offer_packet = Packet.construct_reply_packet(received_packet, 'offer', source_address, topology)
                    log('Constructing DHCP offer packet...', 'info')
                    packet_data, packet_options, option_descriptions = Packet.examine_packet(offer_packet)
                    log(f'Offer packet options:', 'info')
                    for option_number, option_value in packet_options.items():
                        log(f'{option_number} [{option_descriptions[option_number]}]: {option_value}', 'info')
                    socket.sendto(offer_packet, (source_address, self.PORT))

                elif packet_options[53] == 3:
                    log('Received DHCP request packet', 'info')
                    ack_packet = Packet.construct_reply_packet(offer_packet, 'ack', source_address, topology)
                    log('Constructing DHCP ack packet...', 'info')
                    packet_data, packet_options, option_descriptions = Packet.examine_packet(ack_packet)
                    log(f'Ack packet options:', 'info')
                    for option_number, option_value in packet_options.items():
                        log(f'{option_number} [{option_descriptions[option_number]}]: {option_value}', 'info')
                    socket.sendto(ack_packet, (source_address, self.PORT))

                elif packet_options[53] == 7:
                    log('Received DHCP release packet', 'info')
                    log('See you around, partner\U0001F920', 'info')

            except KeyboardInterrupt:
                log('Exiting...', 'info')
                break
