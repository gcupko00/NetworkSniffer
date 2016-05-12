using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using System.Windows.Data;
using System.IO;
using System.Windows;

namespace NetworkSniffer.Model
{
    public class UDPPacket
    {
        #region Members
        private const uint UDPHeaderSize = 8;
        private byte[] byteUDPHeader = new byte[UDPHeaderSize];
        private byte[] byteUDPMessage;
        #endregion

        #region Constructors
        public UDPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                // Create MemoryStream out of received byte array
                // *check if it is possible to use MemoryStream(byteBuffer)
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                // Create BinaryReader out of MemoryStream
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // Copy header bytes from byteBuffer to byteUDPHeader
                Array.Copy(byteBuffer, byteUDPHeader, UDPHeaderSize);

                // Copy message data to byteUDPMessage
                byteUDPMessage = new byte[length - UDPHeaderSize];
                Array.Copy(byteBuffer, UDPHeaderSize, byteUDPMessage, 0, length - UDPHeaderSize);

                UDPHeader = new List<UDPHeader>();
                DNSPacket = new List<DNSPacket>();

                PopulatePacketContents();
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        /// <summary>
        /// Holds only one element - header part of the UDPPacket
        /// </summary>
        public List<UDPHeader> UDPHeader { get; set; }

        /// <summary>
        /// Holds UDP message if application protocol is DNS
        /// </summary>
        public List<DNSPacket> DNSPacket { get; set; }

        /// <summary>
        /// Composite collection that stores both header and message
        /// </summary>

        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = UDPHeader },
                    new CollectionContainer() { Collection = DNSPacket }
                };
            }
        }
        #endregion

        #region Methods
        private void PopulatePacketContents()
        {
            // Add header info
            UDPHeader.Add(new UDPHeader(byteUDPHeader, (int)UDPHeaderSize));

            if (UDPHeader[0].DestinationPort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteUDPMessage, byteUDPMessage.Length));
            }
            else if (UDPHeader[0].SourcePort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteUDPMessage, byteUDPMessage.Length));
            }
        }
        #endregion
    }
}
