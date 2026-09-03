namespace ipk_sniffer;

static class Program
{
    static int Main(string[] args)
    {
        ProgramStarter programStarter = new();
        Sniffer sniffer = new();
        programStarter.PrepareToStart(sniffer.StartSniffing);
        return programStarter.Start(args);
    }
}