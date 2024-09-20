import json
import logging
import os
import re
import urllib.parse

from datetime import datetime, timedelta

import mysql.connector
import requests_cache

from scapy.all import sniff
from scapy.contrib.rtps import RTPS
from scapy.contrib.rtps.rtps import RTPSMessage, RTPSSubMessage_ACKNACK, RTPSSubMessage_HEARTBEAT
from scapy.layers.all import IP, UDP
from scapy.utils import PcapWriter

from acknack import send_acknack
from heartbeat import send_heartbeat

MYSQL_USERNAME = os.getenv("MYSQL_USERNAME")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE")

if not (MYSQL_USERNAME and MYSQL_PASSWORD and MYSQL_HOST and MYSQL_DATABASE):
    raise Exception("MySQL credentials missing")

logger = logging.getLogger(__name__)
logging.basicConfig(filename="collector.log", level=logging.INFO, filemode='w')

session = requests_cache.CachedSession("ip_cache", expire_after=timedelta(days=5))

SENT_ENCLAVE = False


def sniff_packets(iface):
    logger.info("Starting sniffer on ports 7400, 7410, 7411")
    sniff(filter="inbound and port 7400 or port 7410 or port 7411", prn=_process_packet, iface=iface, store=0)
    logger.info("Stopped sniffer")


def _process_packet(packet):
    now = datetime.now()
    try:
        ros2_node_ip = packet[IP].src
        pktdump = PcapWriter(f"data/{ros2_node_ip}.pcap", append=True, sync=True)

        # TODO: Check for unique GUID
        # TODO: If the RTPS layer contains no mention of the collector server IP, then this is an invalid packet
        # TODO: Pipe ZMap IP addresses into the crafted packet (through cmd-line arguments?)

        # zmap -p 7400,7410,7411,7412 0.0.0.0/0 -q | python3 amplification_vulnerability.py
        raw_layer = bytes(packet[UDP].payload)
        rtps_packet = RTPS(raw_layer)
        rtps_message_packet = rtps_packet[RTPSMessage]
        if rtps_message_packet.haslayer(RTPSSubMessage_HEARTBEAT):
            heartbeat = rtps_message_packet[RTPSSubMessage_HEARTBEAT]
            print(heartbeat.fields)
            pktdump.write(packet)
            insert_packet(ros2_node_ip, raw_layer, now)
        if rtps_message_packet.haslayer(RTPSSubMessage_ACKNACK):
            acknack = rtps_message_packet[RTPSSubMessage_ACKNACK]
            print(acknack.fields)
            pktdump.write(packet)
            insert_packet(ros2_node_ip, raw_layer, now)
        logger.info(f"Received RTPS packet at {now} from {ros2_node_ip}")
    except Exception as e:
        logger.error(f"Failed to dissect packet from {ros2_node_ip}", exc_info=True)
        return


def _initiate_connection():
    return mysql.connector.connect(
            user=MYSQL_USERNAME,
            password=MYSQL_PASSWORD,
            host=MYSQL_HOST,
            database=MYSQL_DATABASE
        )


def _geolocate(ip):
    response = session.get(f"https://ipwho.is/{ip}")
    status = response.status_code
    if status != 200:
        logger.error(f"Failed to get geolocation data from {ip} with status code {status}")
        return {"region": None, "country": None}
    response = response.json()
    return {"region": response["region"], "country": response["country_code"]} 


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


if __name__ == "__main__":
    sniff_packets("eth0")

