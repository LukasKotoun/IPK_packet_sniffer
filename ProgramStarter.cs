using System.CommandLine;

namespace ipk_sniffer;

public class ProgramStarter
{
    private RootCommand _rootCommand;
    private int _returnCode = 0;

    public ProgramStarter()
    {
        _rootCommand = new RootCommand();
    }

    /// <summary>
    /// Prepare argument parsing for program start
    /// </summary>
    /// <param name="methodToPassParams">method to be executed with parsed params, last 'int' is return type of Func </param>
    public void PrepareToStart(
        Func<string, int?, int?, int?, int, PacketsToFilter, int> methodToPassParams
    )
    {
        //set options
        var interfaceOption = new Option<string>(
            aliases: new string[] { "--interface", "-i" },
            description: "Interface to sniff on",
            getDefaultValue: () => "")
        {
            Arity = ArgumentArity.ZeroOrOne
        };
        var tcpOption = new Option<bool>(
            aliases: new string[] { "--tcp", "-t" },
            description: "Will display TCP segments and is optionally complemented by -p or --port-* functionality");
        var udpOption = new Option<bool>(
            aliases: new string[] { "--udp", "-u" },
            description: "Will display UDP datagrams and is optionally complemented by-p or --port-* functionality");
        var portOption = new Option<int?>(
            name: "-p",
            description:
            "Extends previous two parameters to filter TCP/UDP based on port number - port can occur in destination or source");
        var portDstOption = new Option<int?>(
            name: "--port-destination",
            description:
            "extends previous two parameters to filter TCP/UDP based on port number - port can occur in destination");
        var portSrcOption = new Option<int?>(
            name: "--port-source",
            description:
            "Extends previous two parameters to filter TCP/UDP based on port number - port can occur in source");
        var icmp4Option = new Option<bool>(
            name: "--icmp4",
            description: "will display only ICMPv4 packet");
        var icmp6Option = new Option<bool>(
            name: "--icmp6",
            description: "will display only ICMPv6 echo request/response");
        var arpOption = new Option<bool>(
            name: "--arp",
            description: "Will display only ARP frames");
        var ndpOption = new Option<bool>(
            name: "--ndp",
            description: "Will display only NDP packets, subset of ICMPv6");
        var igmpOption = new Option<bool>(
            name: "--igmp",
            description: "Will display only IGMP packets");
        var mldOption = new Option<bool>(
            name: "--mld",
            description: "Will display only MLD packets, subset of ICMPv6");
        var packetCountOption = new Option<int>(
            name: "-n",
            description: "specifies the number of packets to display",
            getDefaultValue: () => 1);


        _rootCommand.Description = "IPK packet sniffer from selected interface";

        //add to root command 
        _rootCommand.Add(interfaceOption);
        _rootCommand.Add(tcpOption);
        _rootCommand.Add(udpOption);
        _rootCommand.Add(portOption);
        _rootCommand.Add(portDstOption);
        _rootCommand.Add(portSrcOption);
        _rootCommand.Add(icmp4Option);
        _rootCommand.Add(icmp6Option);
        _rootCommand.Add(arpOption);
        _rootCommand.Add(igmpOption);
        _rootCommand.Add(ndpOption);
        _rootCommand.Add(mldOption);
        _rootCommand.Add(packetCountOption);

        _rootCommand.AddValidator(commandResult =>
        {
            //port and port source or port destination can't be set simultaneously
            var portDst = commandResult.FindResultFor(portDstOption) != null;
            var portSrc = commandResult.FindResultFor(portSrcOption) != null;
            var port = commandResult.FindResultFor(portOption) != null;

            if (port && (portDst || portSrc))
            {
                Console.Error.WriteLine(
                    "port and port source or port destination can't be set simultaneously");
                _returnCode = 2;
            }
        });

        //bind to function
        _rootCommand.SetHandler(
            (interfaceName, port, portDst, portSrc, packetCount, packetsToFilter) =>
            {
                _returnCode = methodToPassParams(interfaceName, port, portDst, portSrc, packetCount,
                    packetsToFilter);
            },
            interfaceOption, portOption, portDstOption, portSrcOption, packetCountOption,
            new PacketsToFilterBinder(tcpOption, udpOption, icmp4Option, icmp6Option, arpOption, ndpOption, igmpOption,
                mldOption));
    }
    /// <summary>
    /// Start program, first parse args check for errors and then run method with that params
    /// </summary>
    /// <param name="args">Program arguments from main</param>
    /// <returns>app return code</returns>
    public int Start(string[] args)
    {
        _rootCommand.Parse(args);
        if (_returnCode != 0)
            return _returnCode;
        _rootCommand.Invoke(args);
        return _returnCode;
    }
}