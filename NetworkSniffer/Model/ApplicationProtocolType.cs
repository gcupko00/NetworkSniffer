using System;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to define ApplicationProtocol type carried by TCP/UDP
    /// </summary>
    public class ApplicationProtocolType
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of ApplicationProtocolType class
        /// </summary>
        /// <param name="SrcPort">Source port used to determine the protocol type</param>
        /// <param name="DestPort">Destination port used to determine the protocol type</param>
        public ApplicationProtocolType(ushort SrcPort, ushort DestPort)
        {
            // This solution is not optimal, but it works for the most cases
            PortNumber = Math.Min(SrcPort, DestPort);

            switch (PortNumber)
            {
                case 7:
                    PortName = "ECHO";
                    break;
                case 18:
                    PortName = "MSP (Message Send Protocol)";
                    break;
                case 20:
                    PortName = "FTP (data)";
                    break;
                case 21:
                    PortName = "FTP (control)";
                    break;
                case 22:
                    PortName = "SSH";
                    break;
                case 23:
                    PortName = "Telnet";
                    break;
                case 25:
                    PortName = "SMTP";
                    break;
                case 37:
                    PortName = "Time Protocol";
                    break;
                case 43:
                    PortName = "WHOIS";
                    break;
                case 53:
                    PortName = "DNS";
                    break;
                case 67:
                    PortName = "BOOTP (server)";
                    break;
                case 68:
                    PortName = "BOOTP (client)";
                    break;
                case 80:
                    PortName = "HTTP";
                    break;
                case 115:
                    PortName = "SFTP";
                    break;
                case 118:
                    PortName = "SQL Services";
                    break;
                case 123:
                    PortName = "NTP";
                    break;
                case 137:
                    PortName = "NetBIOS Name Service";
                    break;
                case 138:
                    PortName = "NetBIOS Datagram Service";
                    break;
                case 139:
                    PortName = "NetBIOS Session Service";
                    break;
                case 153:
                    PortName = "SGMP";
                    break;
                case 156:
                    PortName = "SQL Service";
                    break;
                case 177:
                    PortName = "XDMCP";
                    break;
                case 179:
                    PortName = "BGP";
                    break;
                case 194:
                    PortName = "IRC";
                    break;
                case 443:
                    PortName = "HTTPS";
                    break;
                case 520:
                    PortName = "RIP";
                    break;
                case 521:
                    PortName = "RIPng";
                    break;
                case 843:
                    PortName = "Adobe Flash";
                    break;
                default:
                    PortName = "Unknown port (" + PortNumber + ")";
                    break;
            }
        }
        #endregion

        #region Properties
        public ushort PortNumber { get; private set; }

        public string PortName { get; private set; }
        #endregion
    }
}
