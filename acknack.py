from scapy.all import send
from scapy.contrib.rtps import RTPS
from scapy.contrib.rtps.rtps import (
    GUIDPrefixPacket,
    ProtocolVersionPacket,
    RTPSMessage,
    RTPSSubMessage_ACKNACK,
    RTPSSubMessage_INFO_DST,
    VendorIdPacket,
)
from scapy.layers.inet import IP, UDP


def send_acknack(ros2_node_ip, port):
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
                guidPrefix=GUIDPrefixPacket(
                    hostId=17780274, appId=152422119, instanceId=0
                ),
            ),
            RTPSSubMessage_ACKNACK(
                submessageId=6,
                submessageFlags=1,
                octetsToNextHeader=24,
                reader_id=b"\x00\x02\x00\xc7",
                writer_id=b"\x00\x02\x00\xc2",
                readerSNState=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                count=25,
            ),
        ]
    )

    udp_packet = UDP(sport=33653, dport=port)
    ip_packet = IP(dst=ros2_node_ip)

    packet = ip_packet / udp_packet / rtps_packet
    send(packet)
