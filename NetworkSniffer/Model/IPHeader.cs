using System;
using System.IO;
using System.Net;
using System.Windows;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store IP header fields
    /// </summary>
    public class IPHeader
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of IPHeader class
        /// </summary>
        /// <param name="byteBuffer">Header data to be parsed</param>
        /// <param name="length">Header length</param>
        public IPHeader(byte[] byteBuffer, byte length)
        {
            try
            {
                byte byteVersionAndHeaderLength;
                ushort uiFlagsAndOffset;

                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // First eight bytes are IP version and header length
                // First four bits are version and second four bits are header length
                byteVersionAndHeaderLength = binaryReader.ReadByte();

                // Shift 4 bits to the right to get version number
                Version = (byte)(byteVersionAndHeaderLength >> 4);

                // Shift 4 bits to the left to remove first 4 bits (version bits) than shift back to the right
                InternetHeaderLength = (byte)(byteVersionAndHeaderLength << 4);
                InternetHeaderLength >>= 4;
                // Multiply by 4 to get actual length in bytes
                InternetHeaderLength *= 4;

                // Next byte is TOS
                TypeOfService = binaryReader.ReadByte();

                // Next two bytes hold total length of the packet
                TotalLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                // Next two bytes are identification number
                Identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                // Next two bytes hold flags (first three bits) and fragment offset (remaining bits)
                uiFlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                // Shift right to get the flags value
                ByteFlags = (byte)(uiFlagsAndOffset >> 13);

                // Shift to the left and back to the right to get the offset
                FragmentOffset = (ushort)(uiFlagsAndOffset << 3);
                FragmentOffset >>= 3;
                // Get the actual offset in bytes
                FragmentOffset *= 8;

                // Next byte is TTL
                TimeToLive = binaryReader.ReadByte();

                // Next byte represents transport layer protocol
                TransportProtocol = binaryReader.ReadByte();

                // Next two bytes are checksum
                HeaderChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                
                // Next four bytes are source address
                SourceIPAddress = new IPAddress((uint)(binaryReader.ReadInt32()));

                // Last four bytes are destination address
                DestinationIPAddress = new IPAddress((uint)(binaryReader.ReadInt32()));
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        public byte Version { get; set; }

        public byte InternetHeaderLength { get; set; }

        public byte TypeOfService { get; set; }
        
        public ushort TotalLength { get; set; }

        public ushort Identification { get; set; }
        
        public byte ByteFlags { get; set; }
        
        public string Flags
        {
            get
            {
                switch (ByteFlags)
                {
                    case 1:
                        return "(MF)";
                    case 2:
                        return "(DF)";
                    case 3:
                        return "(DF, MF)";
                    default:
                        return "";
                }
            }
        }

        public ushort FragmentOffset { get; set; }

        public byte TimeToLive { get; set; }

        public byte TransportProtocol { get; set; }
        
        public string TransportProtocolName
        {
            get
            {
                switch (TransportProtocol)
                {
                    case 1:
                        return "ICMP";
                    case 2:
                        return "IGMP";
                    case 6:
                        return "TCP";
                    case 17:
                        return "UDP";
                    default:
                        return "Unknown";
                }
            }
        }

        public short HeaderChecksum { get; set; }

        public IPAddress SourceIPAddress { get; set; }

        public IPAddress DestinationIPAddress { get; set; }
        #endregion
    }
}
