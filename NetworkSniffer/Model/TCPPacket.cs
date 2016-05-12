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
    public class TCPPacket
    {
        #region Members
        private const uint TCPHeaderSize = 20;
        private byte[] byteTCPHeader = new byte[TCPHeaderSize];
        private byte[] byteTCPMessage;
        #endregion

        public TCPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                // Create MemoryStream out of received byte array
                // *check if it is possible to use MemoryStream(byteBuffer)
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                // Create BinaryReader out of MemoryStream
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // Copy header bytes from byteBuffer to byteTCPHeader
                Array.Copy(byteBuffer, byteTCPHeader, TCPHeaderSize);

                // Copy message data to byteTCPMessage
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
        private void PopulatePacketContents()
        {
            // Add header info
            TCPHeader.Add(new TCPHeader(byteTCPHeader, (int)TCPHeaderSize));
            
            if (TCPHeader[0].DestinationPort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteTCPMessage, byteTCPMessage.Length));
            }
            else if (TCPHeader[0].SourcePort == 53)
            {
                DNSPacket.Add(new DNSPacket(byteTCPMessage, byteTCPMessage.Length));
            }
        }
        #endregion
    }
}
