using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to split UDP packet to header and message
    /// </summary>
    public class UDPPacket
    {
        #region Fields
        private const uint UDPHeaderSize = 8;
        private byte[] byteUDPHeader = new byte[UDPHeaderSize];
        private byte[] byteUDPMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of UDPPacket class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing packet data</param>
        /// <param name="length">Packet size in bytes</param>
        public UDPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                
                Array.Copy(byteBuffer, byteUDPHeader, UDPHeaderSize);
                
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
        /// Holds info about application protocol
        /// </summary>
        public ApplicationProtocolType ApplicationProtocolType { get; private set; }

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
        /// <summary>
        /// Puts packet content in the PacketContent list
        /// Adds header info to TCPHeader "list"
        /// </summary>
        private void PopulatePacketContents()
        {
            UDPHeader.Add(new UDPHeader(byteUDPHeader, (int)UDPHeaderSize));

            if (UDPHeader[0].DestinationPort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteUDPMessage, byteUDPMessage.Length));
            }
            else if (UDPHeader[0].SourcePort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteUDPMessage, byteUDPMessage.Length));
            }

            ApplicationProtocolType = new ApplicationProtocolType(UDPHeader[0].SourcePort,
                                                                  UDPHeader[0].DestinationPort);
        }
        #endregion
    }
}
