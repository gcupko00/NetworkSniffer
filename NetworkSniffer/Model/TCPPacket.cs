using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to split TCP packet to header and message
    /// </summary>
    public class TCPPacket
    {
        #region Fields
        private const uint TCPHeaderSize = 20;
        private byte[] byteTCPHeader = new byte[TCPHeaderSize];
        private byte[] byteTCPMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of TCPPacket class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing packet data</param>
        /// <param name="length">Packet size in bytes</param>
        public TCPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                
                Array.Copy(byteBuffer, byteTCPHeader, TCPHeaderSize);
                
                byteTCPMessage = new byte[length - TCPHeaderSize];
                Array.Copy(byteBuffer, TCPHeaderSize, byteTCPMessage, 0, length - TCPHeaderSize);

                TCPHeader = new List<TCPHeader>();
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
        /// Holds only one element - header part of the TCPPacket
        /// </summary>
        public List<TCPHeader> TCPHeader { get; set; }

        /// <summary>
        /// Holds TCP message if application protocol is DNS
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
                    new CollectionContainer() { Collection = TCPHeader },
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
            TCPHeader.Add(new TCPHeader(byteTCPHeader, (int)TCPHeaderSize));
            
            if (TCPHeader[0].DestinationPort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteTCPMessage, byteTCPMessage.Length));
            }
            else if (TCPHeader[0].SourcePort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteTCPMessage, byteTCPMessage.Length));
            }

            ApplicationProtocolType = new ApplicationProtocolType(TCPHeader[0].SourcePort,
                                                                  TCPHeader[0].DestinationPort);
        }
        #endregion
    }
}
