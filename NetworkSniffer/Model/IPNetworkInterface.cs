namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to store IP network interface name and address
    /// </summary>
    public class IPNetworkInterface
    {
        public string InterfaceName { get; set; }

        public string InterfaceAddress { get; set; }

        public string InterfaceNameAndAddress
        {
            get
            {
                return InterfaceName + " (" + InterfaceAddress + ")";
            }
        }
    }
}
