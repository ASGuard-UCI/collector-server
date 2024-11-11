from scapy.all import send
from scapy.contrib.rtps import RTPS
from scapy.contrib.rtps.rtps import (
    GUIDPrefixPacket,
    ProtocolVersionPacket,
    RTPSMessage,
    RTPSSubMessage_HEARTBEAT,
    RTPSSubMessage_INFO_DST,
    VendorIdPacket,
)
from scapy.layers.inet import IP, UDP


def send_heartbeat(ros2_node_ip, port, guid_prefix_packet):
    rtps_packet = RTPS(
        magic=b"RTPS",
        protocolVersion=ProtocolVersionPacket(major=2, minor=3),
        vendorId=VendorIdPacket(vendor_id=271),
        guidPrefix=GUIDPrefixPacket(hostId=17802292, appId=2902144048, instanceId=0),
    ) / RTPSMessage(
        submessages=[
            RTPSSubMessage_INFO_DST(
                submessageId=14,
                submessageFlags=1,
                octetsToNextHeader=12,
                guidPrefix=guid_prefix_packet,
            ),
            RTPSSubMessage_HEARTBEAT(
                submessageId=7,
                submessageFlags=1,
                octetsToNextHeader=28,
                reader_id=b"\x00\x02\x00\xc7",
                writer_id=b"\x00\x02\x00\xc2",
                firstAvailableSeqNumHi=0,
                firstAvailableSeqNumLow=1,
                lastSeqNumHi=0,
                lastSeqNumLow=0,
                count=4,
            ),
        ]
    )

    udp_packet = UDP(sport=33653, dport=7410)
    ip_packet = IP(dst=ros2_node_ip)

    packet = ip_packet / udp_packet / rtps_packet
    send(packet)
