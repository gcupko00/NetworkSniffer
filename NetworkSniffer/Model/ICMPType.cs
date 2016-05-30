namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to define ICMP type by type number and name
    /// </summary>
    public class ICMPType
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of ICMPType class
        /// </summary>
        /// <param name="ICMPNumber">ICMP type number</param>
        public ICMPType(byte ICMPNumber)
        {
            this.ICMPNumber = ICMPNumber;

            if (ICMPNumber <= 40)
            {
                if(ICMPNumber >= 20 && ICMPNumber <= 29)
                {
                    ICMPTypeName = "Reserved (for Robustness Experiment)";
                }
                else
                {
                    switch(ICMPNumber)
                    {
                        case 0:
                            ICMPTypeName = "Echo Reply";
                            break;
                        case 3:
                            ICMPTypeName = "Destination Unreachable";
                            break;
                        case 5:
                            ICMPTypeName = "Redirect";
                            break;
                        case 6:
                            ICMPTypeName = "Alternate Host Address";
                            break;
                        case 8:
                            ICMPTypeName = "Echo Request";
                            break;
                        case 9:
                            ICMPTypeName = "Router Advertisement";
                            break;
                        case 10:
                            ICMPTypeName = "Router Selection";
                            break;
                        case 11:
                            ICMPTypeName = "Time Exceeded";
                            break;
                        case 12:
                            ICMPTypeName = "Parameter Problem";
                            break;
                        case 13:
                            ICMPTypeName = "Timestamp";
                            break;
                        case 14:
                            ICMPTypeName = "Timestamp Reply";
                            break;
                        case 15:
                            ICMPTypeName = "Information Request";
                            break;
                        case 16:
                            ICMPTypeName = "Information Reply";
                            break;
                        case 17:
                            ICMPTypeName = "Address Mask Request";
                            break;
                        case 18:
                            ICMPTypeName = "Address Mask Reply";
                            break;
                        case 19:
                            ICMPTypeName = "Reserved (for Security)";
                            break;
                        case 30:
                            ICMPTypeName = "Traceroute";
                            break;
                        case 31:
                            ICMPTypeName = "Datagram Conversion Error";
                            break;
                        case 32:
                            ICMPTypeName = "Mobile Host Redirect";
                            break;
                        case 33:
                            ICMPTypeName = "IPv6 Where-Are-You";
                            break;
                        case 34:
                            ICMPTypeName = "IPv6 I-Am-Here";
                            break;
                        case 35:
                            ICMPTypeName = "Mobile Registration Request";
                            break;
                        case 36:
                            ICMPTypeName = "Mobile Registration Reply";
                            break;
                        case 37:
                            ICMPTypeName = "Domain Name Request";
                            break;
                        case 38:
                            ICMPTypeName = "Domain Name Reply";
                            break;
                        case 39:
                            ICMPTypeName = "SKIP";
                            break;
                        case 40:
                            ICMPTypeName = "Photuris";
                            break;
                        default:
                            ICMPTypeName = "Unassigned";
                            break;
                    }
                }
            }
            else
            {
                ICMPTypeName = "Reserved";
            }
        }
        #endregion

        #region Properties
        public byte ICMPNumber { get; private set; }

        public string ICMPTypeName { get; private set; }
        #endregion
    }
}
