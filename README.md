# ROS 2 Collector Service

The researchers in [the TrendMicro paper](https://documents.trendmicro.com/assets/white_papers/wp-a-security-analysis-of-the-data-distribution-service-dds-protocol.pdf)
set up a collector server as part of their DDS scans. By modifying the unicast
locator IPs, RTPS packets would get sent to an IP address of their choosing,
allowing them to discover and store the IP addresses of ROS 2 nodes.

The code in this repository sets up a service that will replicate this 
collector behavior and communicate with the ROS 2 nodes that send packets
to it.

