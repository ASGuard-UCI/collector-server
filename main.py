import logging
import os
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

import mysql.connector
import requests_cache
from scapy.all import sniff
from scapy.contrib.rtps import RTPS
from scapy.contrib.rtps.rtps import (
    RTPSMessage,
    RTPSSubMessage_ACKNACK,
    RTPSSubMessage_HEARTBEAT,
    RTPSSubMessage_DATA,
)
from scapy.layers.all import IP, UDP
from scapy.utils import PcapWriter
from scapy.contrib.rtps import GUIDPrefixPacket

from acknack import send_acknack
from heartbeat import send_heartbeat
from humble_talker_cyclone_data_w_ros_discovery_info import (
    send_data_w_ros_discovery_info,
)

MYSQL_USERNAME = os.getenv("MYSQL_USERNAME")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE")

if not (MYSQL_USERNAME and MYSQL_PASSWORD and MYSQL_HOST and MYSQL_DATABASE):
    raise Exception("MySQL credentials missing")

logger = logging.getLogger(__name__)
logging.basicConfig(filename="collector.log", level=logging.INFO, filemode="w")

session = requests_cache.CachedSession("ip_cache", expire_after=timedelta(days=5))

# Store queues of packets associated with a specific node's IP
ROS2_NODE_MAP = defaultdict(deque)

# Keep track of existing sessions with a set that stores the IPs of nodes
EXISTING_SESSIONS = set()

# There can be a race condition where a session ends, causing the IP to be
# removed from the existing sessions set, but at the same time, packets for
# the same IP come in, initiating a new session and adding it back to the
# existing sessions set.
EXISTING_SESSIONS_LOCK = threading.Lock()


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
        # has_scanned = find_ip(ros2_node_ip)
        # if not has_scanned:
        #     return

        pktdump = PcapWriter(f"data/{ros2_node_ip}.pcap", append=True, sync=True)

        raw_layer = bytes(packet[UDP].payload)
        src_port = packet[UDP].sport
        rtps_packet = RTPS(raw_layer)

        # RTPS / RTPSMessage
        rtps_layer = rtps_packet[RTPS]
        host_id = rtps_layer.guidPrefix.hostId
        app_id = rtps_layer.guidPrefix.appId
        instance_id = rtps_layer.guidPrefix.instanceId

        logger.info(f"Host ID: {host_id}")
        logger.info(f"App ID: {app_id}")
        logger.info(f"Instance ID: {instance_id}")

        guid_prefix_packet = GUIDPrefixPacket(
            hostId=host_id, appId=app_id, instanceId=instance_id
        )

        rtps_message_packet = rtps_packet[RTPSMessage]

        ROS2_NODE_MAP[ros2_node_ip].append(rtps_message_packet)

        insert_packet(ros2_node_ip, raw_layer, now)
        pktdump.write(packet)

        if ros2_node_ip not in EXISTING_SESSIONS:
            with EXISTING_SESSIONS_LOCK:
                EXISTING_SESSIONS.add(ros2_node_ip)

            thread = threading.Thread(
                target=_handle_session,
                args=[ros2_node_ip, src_port, guid_prefix_packet],
            )
            thread.start()

        logger.info(
            f"Received RTPS packet at {now} from {ros2_node_ip} on port {src_port}"
        )
    except Exception as e:
        logger.error(f"Failed to dissect packet from {ros2_node_ip}", exc_info=True)
        return


def _initiate_connection():
    return mysql.connector.connect(
        user=MYSQL_USERNAME,
        password=MYSQL_PASSWORD,
        host=MYSQL_HOST,
        database=MYSQL_DATABASE,
    )


def _geolocate(ip):
    response = session.get(f"https://ipwho.is/{ip}")
    status = response.status_code
    if status != 200:
        logger.error(
            f"Failed to get geolocation data from {ip} with status code {status}"
        )
        return {"region": None, "country": None}
    response = response.json()
    try:
        return {"region": response["region"], "country": response["country_code"]}
    except KeyError:
        return {"region": "test_region", "country": "test_country"}


def _handle_session(ros2_node_ip, port, guid_prefix_packet):
    """
    Initiate a session (thread) that pops packets from its corresponding queue while the queue is not empty
    If the queue is empty for more than 10 seconds? stop the session
    """
    print("Initiating thread")

    now = datetime.now()

    while datetime.now() - now <= timedelta(seconds=10):
        if len(ROS2_NODE_MAP[ros2_node_ip]) > 0:
            message_packet = ROS2_NODE_MAP[ros2_node_ip].popleft()
            logger.info(f"Sending packet to {ros2_node_ip}")
            if message_packet.haslayer(
                RTPSSubMessage_HEARTBEAT
            ) or message_packet.haslayer(RTPSSubMessage_DATA):
                send_acknack(ros2_node_ip, port, guid_prefix_packet)
            if message_packet.haslayer(RTPSSubMessage_ACKNACK):
                send_heartbeat(ros2_node_ip, port, guid_prefix_packet)

            send_data_w_ros_discovery_info(ros2_node_ip, guid_prefix_packet)

            now = datetime.now()

    with EXISTING_SESSIONS_LOCK:
        EXISTING_SESSIONS.remove(ros2_node_ip)

    print("Stopping thread")


def insert_packet(ros2_node_ip, raw_layer, timestamp):
    cnx = _initiate_connection()
    cursor = cnx.cursor()
    insert_packet = "INSERT INTO packets (received_time, ip, location, payload) VALUES (%s, %s, %s, %s)"

    geo_data = _geolocate(ros2_node_ip)
    region = geo_data["region"]
    country = geo_data["country"]

    insert_data = (timestamp, ros2_node_ip, region + ", " + country, raw_layer)

    cursor.execute(insert_packet, insert_data)
    logger.info(f"Successfully inserted packet to database")

    cnx.commit()
    cursor.close()
    cnx.close()


def find_ip(ros2_node_ip):
    cnx = _initiate_connection()
    cursor = cnx.cursor()

    has_been_scanned_stmt = "SELECT ipv4 FROM scanned_ips WHERE ipv4 = %s"
    cursor.execute(has_been_scanned_stmt, (ros2_node_ip,))

    has_been_scanned = len(cursor.fetchall()) != 0
    cursor.close()
    cnx.close()
    return has_been_scanned


if __name__ == "__main__":
    sniff_packets("eth0")
