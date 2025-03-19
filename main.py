import logging
from datetime import datetime

from scapy.all import sniff
from scapy.layers.all import IP, UDP
from scapy.utils import PcapWriter

logger = logging.getLogger(__name__)
logging.basicConfig(filename="collector.log", level=logging.INFO, filemode="w")


def sniff_packets(iface):
    logger.info("Starting sniffer on ports 7400, 7410, 7411")
    sniff(
        filter="inbound and port 7400 or port 7410 or port 7411",
        prn=_process_packet,
        iface=iface,
        store=0,
    )
    logger.info("Stopped sniffer")


def _process_packet(packet):
    now = datetime.now()
    try:
        ros2_node_ip = packet[IP].src
        dst = packet[IP].dst
        src_port = packet[UDP].sport

        if dst == "239.255.0.1":
            return

        pktdump = PcapWriter(f"data/{ros2_node_ip}.pcap", append=True, sync=True)
        pktdump.write(packet)

        logger.info(
            f"Received RTPS packet at {now} from {ros2_node_ip} on port {src_port}"
        )
    except Exception as e:
        logger.error(f"Failed to dissect packet from {ros2_node_ip}", exc_info=True)
        return


if __name__ == "__main__":
    sniff_packets("eth0")
