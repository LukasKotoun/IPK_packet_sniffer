using System.Globalization;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ipk_sniffer;

public class Sniffer
{
    /// <summary>
    /// Check if packet is valid according to filters   
    /// </summary>
    /// <param name="port">Port to filter tcp and udp at (destination or source)</param>
    /// <param name="dstPort">Destination port to filter tcp and udp at</param>
    /// <param name="srcPort">Source port to filter tcp and udp at</param>
    /// <param name="packetsToFilter">Instance of class with flags that indicating with packets should be filtered</param>
    /// <param name="rawCapture">Capture packet</param>
    /// <returns>True if packet is valid for current filter settings</returns>
    private bool Filter(int? port, int? dstPort, int? srcPort, PacketsToFilter packetsToFilter,
        RawCapture rawCapture)
    {
        var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

        //check if ports are right for tcp or udp - if not return false 
        //if they are right continue to check packets

        if (packet.PayloadPacket is IPPacket ipPacketPort)
        {
            //check src or dsc port of udp or tcp packet
            if (port != null)
            {
                //if packet is udp or tcp and neither src and dst port don't match port return false
                switch (ipPacketPort.PayloadPacket)
                {
                    case UdpPacket udpPacket when
                        udpPacket.SourcePort != port && udpPacket.DestinationPort != port:
                    case TcpPacket tcpPacket when
                        tcpPacket.SourcePort != port && tcpPacket.DestinationPort != port:
                        return false;
                }
            }
            else
            {
                //if packet is udp or tcp and dst port don't match dstPort return false
                if (dstPort != null)
                {
                    switch (ipPacketPort.PayloadPacket)
                    {
                        case UdpPacket udpPacket
                            when udpPacket.DestinationPort != dstPort:
                        case TcpPacket tcpPacket
                            when tcpPacket.DestinationPort != dstPort:
                            return false;
                    }
                }

                //if packet is udp or tcp and src port don't match srcPort return false
                if (srcPort != null)
                {
                    switch (ipPacketPort.PayloadPacket)
                    {
                        case UdpPacket udpPacket
                            when udpPacket.SourcePort != srcPort:
                        case TcpPacket tcpPacket
                            when tcpPacket.SourcePort != srcPort:
                            return false;
                    }
                }
            }
        }

        //if other filters are not set display all - already filtered by port
        if (packetsToFilter.areAllFalse())
        {
            return true;
        }

        // some filters are set
        // filter one by one if all 'or' are false return false at end 

        //only arp is not IPPacket
        if (packetsToFilter.Arp && packet.PayloadPacket is ArpPacket)
        {
            return true;
        }


        // other are IPPacket 
        if (packet.PayloadPacket is not IPPacket ipPacket)
        {
            return false;
        }

        //check IPPackets
        if (packetsToFilter.Tcp && ipPacket.PayloadPacket is TcpPacket)
        {
            return true;
        }

        if (packetsToFilter.Udp && ipPacket.PayloadPacket is UdpPacket)
        {
            return true;
        }

        if (packetsToFilter.Icmp4 && ipPacket.PayloadPacket is IcmpV4Packet)
        {
            return true;
        }

        if (packetsToFilter.Igmp && ipPacket.PayloadPacket is IgmpPacket)
        {
            return true;
        }


        // other are icmp6 packets 
        if (ipPacket.PayloadPacket is not IcmpV6Packet icmpV6Packet)
        {
            return false;
        }

        //check icmp6 packets
        if (packetsToFilter.Icmp6 && icmpV6Packet is { Type: IcmpV6Type.EchoReply or IcmpV6Type.EchoRequest })
        {
            return true;
        }

        if (packetsToFilter.Ndp && icmpV6Packet is
            {
                Type: IcmpV6Type.RouterSolicitation or IcmpV6Type.RouterAdvertisement
                or IcmpV6Type.NeighborSolicitation or IcmpV6Type.NeighborAdvertisement
                or IcmpV6Type.RedirectMessage
            })
        {
            return true;
        }

        if (packetsToFilter.Mld && icmpV6Packet is
            {
                Type: IcmpV6Type.MulticastListenerQuery or IcmpV6Type.MulticastListenerReport
                or IcmpV6Type.MulticastListenerDone or IcmpV6Type.Version2MulticastListenerReport
            })
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Processes captured packet by parsing it, creating header, formatting data, and printing the result.
    /// </summary>
    /// <param name="rawCapture">The captured packet to be processed</param>
    private void ProcessCapturedPacket(RawCapture rawCapture)
    {
        var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
        string header = CreateHeader(packet, rawCapture);
        string formattedData = CreateFormattedData(packet.PrintHex());

        Console.WriteLine(header);
        Console.WriteLine(formattedData + "\n\n");
    }

    /// <summary>
    /// Format header from packet and rawCapture information's (like add mac address if packet contains it and other) 
    /// </summary>
    /// <param name="packet">Parsed captured packet</param>
    /// <param name="rawCapture">Capturet packet</param>
    /// <returns>Formatted header ready to be printed (ending with \n)</returns>
    private string CreateHeader(Packet packet, RawCapture rawCapture)
    {
        string header = "";

        header +=
            $"timestamp: {TimeZoneInfo.ConvertTimeFromUtc(rawCapture.Timeval.Date, TimeZoneInfo.Local).ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz", DateTimeFormatInfo.InvariantInfo)}\n";

        if (packet is EthernetPacket ethernetPacket)
        {
            header += $"src MAC: {FormatMacAddress(ethernetPacket.SourceHardwareAddress.ToString())}\n";
            header += $"dst MAC: {FormatMacAddress(ethernetPacket.DestinationHardwareAddress.ToString())}\n";
        }

        header += $"frame length: {rawCapture.Data.Length.ToString()} bytes\n";

        if (packet.PayloadPacket is IPPacket ipPacket)
        {
            header += $"src IP: {ipPacket.SourceAddress.ToString()}\n";
            header += $"dst IP: {ipPacket.DestinationAddress.ToString()}\n";
            if (ipPacket.PayloadPacket is UdpPacket udpPacket)
            {
                header += $"src port: {udpPacket.SourcePort.ToString()}\n";
                header += $"dst port: {udpPacket.DestinationPort.ToString()}\n";
            }
            else if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
            {
                header += $"src port: {tcpPacket.SourcePort.ToString()}\n";
                header += $"dst port: {tcpPacket.DestinationPort.ToString()}\n";
            }
        }

        return header;
    }

    /// <summary>
    /// Format unformatted mac address like AABBCCDDEEFF to aa:bb:cc:dd:ee:ff
    /// </summary>
    /// <param name="unformattedMacAddress">Mac addres in string </param>
    /// <returns>Formatted mac address with splitting each 2 hex chars by : and converting all chars to lower case</returns>
    private string FormatMacAddress(string unformattedMacAddress)
    {
        //to every odd char add ':'  
        return
            string.Join("",
                    unformattedMacAddress.Select((c, cIndex) =>
                        cIndex % 2 == 0 && cIndex != 0 ? ":" + c.ToString() : c.ToString()))
                .ToLower();
    }

    /// <summary>
    /// Format hexString data to wireshark format
    /// </summary>
    /// <param name="hexData"></param>
    /// <returns>Formated hex</returns>
    private string CreateFormattedData(string hexData)
    {
        //edit lines from hex format. Remove first 3 lines, skip empty lines (last empty line)
        //and than remove "Data: " and edit start to wireshark like format
        string lines = string.Join('\n', hexData.Split('\n').Skip(3).Where(line => line.Length != 0)
            .Select((line, index) =>
            {
                //remove "Data: " from string 
                line = line.Substring("Data: ".Length);
                //add 0x then wireshark like number and ':' and rest 
                return $"0x{(index * 16).ToString("X4").ToLower()}:{line.Substring(5)}";
            }));
        return lines;
    }


    /// <summary>
    /// Starts sniffing packets on specified network interface
    /// </summary>
    /// <param name="interfaceName">Name of interface to start sniffing on</param>
    /// <param name="port">Port to filter tcp and udp at (destination or source)</param>
    /// <param name="dstPort">Destination port to filter tcp and udp at</param>
    /// <param name="srcPort">Source port to filter tcp and udp at</param>
    /// <param name="n">Number of packet to be captured</param>
    /// <param name="packetsToFilter">Instance of class with flags that indicating with packets should be sniffed</param>
    /// <returns>App return code</returns>
    public int StartSniffing(string? interfaceName, int? port, int? dstPort, int? srcPort,
        int n, PacketsToFilter packetsToFilter)
    {
        var devices = LibPcapLiveDeviceList.Instance;
        if (string.IsNullOrEmpty(interfaceName))
        {
            foreach (var dev in devices)
                Console.WriteLine(dev.Name);
            return 0;
        }

        if (devices.All(device => device.Name != interfaceName))
        {
            Console.Error.WriteLine("Interface with specified name doesn't exist");
            return 1;
        }

        using var device = devices.First(device => device.Name == interfaceName);

        device.Open(DeviceModes.Promiscuous);
        device.Filter = "";

        //capturing inspired from sharppcap documentation 
        //https://github.com/dotpcap/sharppcap/blob/master/Examples/Example4.BasicCapNoCallback/Example4.BasicCapNoCallback.cs
        int capturedPacketsCount = 0;
        while (capturedPacketsCount < n)
        {
            PacketCapture e;
            var status = device.GetNextPacket(out e);
            if (status != GetPacketStatus.PacketRead)
                continue;
            RawCapture rawCapture = e.GetPacket();
            if (!Filter(port, dstPort, srcPort, packetsToFilter, rawCapture))
                continue;
            ProcessCapturedPacket(rawCapture);
            capturedPacketsCount++;
        }

        return 0;
    }
}