using System.CommandLine;
using System.CommandLine.Binding;

namespace ipk_sniffer;

/// <summary>
/// Class with flags that indicating with packets should be sniffed
/// Created for commandLine parsing because of limitation to max 8 params 
/// </summary>
public class PacketsToFilter
{
    public bool Tcp { get; set; }
    public bool Udp { get; set; }
    public bool Icmp4 { get; set; }
    public bool Icmp6 { get; set; }
    public bool Arp { get; set; }
    public bool Ndp { get; set; }
    public bool Igmp { get; set; }
    public bool Mld { get; set; }

    public bool areAllFalse()
    {
        return !(Tcp || Udp || Icmp4 || Icmp6 || Arp || Ndp || Igmp || Mld);
    }
}

/// <summary>
/// custom binder for more than 8 params 
/// https://learn.microsoft.com/en-us/dotnet/standard/commandline/model-binding#parameter-binding-more-than-8-options-and-arguments
/// </summary>
public class PacketsToFilterBinder : BinderBase<PacketsToFilter>
{
    private readonly Option<bool> _tcpOption;
    private readonly Option<bool> _udpOption;
    private readonly Option<bool> _icmp4Option;
    private readonly Option<bool> _icmp6Option;
    private readonly Option<bool> _arpOption;
    private readonly Option<bool> _ndpOption;
    private readonly Option<bool> _igmpOption;
    private readonly Option<bool> _mldOption;


    public PacketsToFilterBinder(Option<bool> tcpOption, Option<bool> udpOption, Option<bool> icmp4Option,
        Option<bool> icmp6Option, Option<bool> arpOption, Option<bool> ndpOption, Option<bool> igmpOption,
        Option<bool> mldOption)
    {
        _tcpOption = tcpOption;
        _udpOption = udpOption;
        _icmp4Option = icmp4Option;
        _icmp6Option = icmp6Option;
        _arpOption = arpOption;
        _ndpOption = ndpOption;
        _igmpOption = igmpOption;
        _mldOption = mldOption;
    }

    protected override PacketsToFilter GetBoundValue(BindingContext bindingContext) =>
        new PacketsToFilter
        {
            Tcp = bindingContext.ParseResult.GetValueForOption(_tcpOption),
            Udp = bindingContext.ParseResult.GetValueForOption(_udpOption),
            Icmp4 = bindingContext.ParseResult.GetValueForOption(_icmp4Option),
            Icmp6 = bindingContext.ParseResult.GetValueForOption(_icmp6Option),
            Arp = bindingContext.ParseResult.GetValueForOption(_arpOption),
            Ndp = bindingContext.ParseResult.GetValueForOption(_ndpOption),
            Igmp = bindingContext.ParseResult.GetValueForOption(_igmpOption),
            Mld = bindingContext.ParseResult.GetValueForOption(_mldOption)
        };
}