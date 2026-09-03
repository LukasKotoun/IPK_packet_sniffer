# Changelog

## Implemented functionality

All the basic elements of the assignment are implemented. In addition, IPv6 extended header support is added.

### Program parameters

`-i|--interface INTERFACE_NAME` Interface to sniff on

`-t|--tcp` Will display TCP segments and is optionally complemented by -p or --port-\_ functionality

`-u|--udp` Will display UDP datagrams and is optionally complemented by-p or --port-\_ functionality

`-p PORT_NUMBER` Extends previous two parameters to filter TCP/UDP based on port number - port can occur in destination or source

`--port-destination PORT_NUMBER` Extends previous two parameters to filter TCP/UDP based on port number - port can occur in destination

`--port-source PORT_NUMBER` Extends previous two parameters to filter TCP/UDP based on port number - port can occur in source

`--icmp4` Will display only ICMPv4 packet

`--icmp6` Will display only ICMPv6 echo request/response

`--arp` Will display only ARP frames

`--igmp` Will display only IGMP packets

`--ndp` Will display only NDP packets, subset of ICMPv6

`--mld` Will display only MLD packets, subset of ICMPv6

`-n PACKETS_COUNT` Specifies the number of packets to display [default: 1]

`-h|--help` Show help and usage information

## Known limitations

Sometimes the app will display additional data at the end of the packet because of the function `PrintHex` from the library `SharpPcap`.
