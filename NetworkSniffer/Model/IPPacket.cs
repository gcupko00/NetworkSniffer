using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Collections;
using System.Windows.Data;
using System.Windows;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class contains properties and methods used to split IP packet to header and message
    /// </summary>
    public class IPPacket
    {
        #region Members
        private byte[] byteIPHeader;
        private byte[] byteIPMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of IPPacket class
        /// </summary>
        /// <param name="byteBuffer">Packet data to be parsed</param>
        /// <param name="length">Packet length</param>
        public IPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                #region Buffer parsing
                // Create MemoryStream out of received byte array
                // *check if it is possible to use MemoryStream(byteBuffer)
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                // Create BinaryReader out of MemoryStream
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // First eight bytes are IP version and header length
                byte byteVersionAndHeaderLength = binaryReader.ReadByte();

                // First four bits are version and second four bits are header length
                // Shift 4 bits to the left to remove first 4 bits
                byte byteHeaderLength = (byte)(byteVersionAndHeaderLength << 4);
                // Shift back to the right
                byteHeaderLength >>= 4;
                // Multiply by 4 to get actual length in bytes
                byteHeaderLength *= 4;

                // Next byte is TOS - ignore it for now
                // binaryReader.ReadByte();

                // Next two bytes hold total length of the packet (usTotalLength == length)
                // ushort usTotalLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //testing
                //MessageBox.Show(length.ToString() + ", " + usTotalLength.ToString());

                // Copy header from byteBuffer to byteIPHeader
                byteIPHeader = new byte[byteHeaderLength];
                Array.Copy(byteBuffer, byteIPHeader, byteHeaderLength);

                // Copy message data from byteBuffer to byteIPMessage
                byteIPMessage = new byte[length - byteHeaderLength];
                Array.Copy(byteBuffer, byteHeaderLength, byteIPMessage, 0, length - byteHeaderLength);
                #endregion

                IPHeader = new List<IPHeader>();
                TCPPacket = new List<TCPPacket>();
                UDPPacket = new List<UDPPacket>();

                // Add header info and packet message to PacketContents collection
                PopulatePacketContents(byteHeaderLength);
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        public byte[] ByteIPHeader
        {
            get
            {
                return byteIPHeader;
            }
        }

        public byte[] ByteIPMessage
        {
            get
            {
                return byteIPMessage;
            }
        }

        // Adding header to composite collection seems like best idea for displaying packet info
        // Both header and massage must be stored as a list so they could be put in CompositeCollection

        /// <summary>
        /// Holds only one element - header part of the IPPacket
        /// </summary>
        public List<IPHeader> IPHeader { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is TCP
        /// </summary>
        public List<TCPPacket> TCPPacket { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is UDP
        /// </summary>
        public List<UDPPacket> UDPPacket { get; set; }

        /// <summary>
        /// Composite collection that stores both header and message
        /// </summary>
        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = IPHeader },
                    new CollectionContainer() { Collection = TCPPacket },
                    new CollectionContainer() { Collection = UDPPacket }
                };
            }
        }

        public string ReceiveTime
        {
            get
            {
                return DateTime.Now.ToString("HH:mm:ss");
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// This method fills PacketContents class with header information and data
        /// </summary>
        /// <param name="headerLength">Length of packet header used to parse it in the IPHeader constructor</param>
        private void PopulatePacketContents(byte headerLength)
        {
            // add header info
            IPHeader.Add(new IPHeader(byteIPHeader, headerLength));

            if(IPHeader[0].TransportProtocol == 6)
            {
                TCPPacket.Add(new TCPPacket(byteIPMessage, byteIPMessage.Length));
            }
            else if (IPHeader[0].TransportProtocol == 17)
            {
                UDPPacket.Add(new UDPPacket(byteIPMessage, byteIPMessage.Length));
            }
        }
        #endregion
    }
}
