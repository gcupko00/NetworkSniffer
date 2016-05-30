using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to split DNS packet to header and message
    /// </summary>
    public class DNSPacket
    {
        #region Fields
        private const uint DNSHeaderSize = 12;
        private byte[] byteDNSHeader = new byte[DNSHeaderSize];
        private byte[] byteDNSMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of DNSPacket class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing packet data</param>
        /// <param name="length">Packet size in bytes</param>
        public DNSPacket(byte[] byteBuffer, int length)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                
                Array.Copy(byteBuffer, byteDNSHeader, DNSHeaderSize);
                
                byteDNSMessage = new byte[length - DNSHeaderSize];
                Array.Copy(byteBuffer, DNSHeaderSize, byteDNSMessage, 0, length - DNSHeaderSize);

                DNSHeader = new List<DNSHeader>();

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
        /// Holds header part of the DNSPacket
        /// </summary>
        public List<DNSHeader> DNSHeader { get; set; }

        /// <summary>
        /// Composite collection that stores header (may be updated to store message)
        /// </summary>
        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = DNSHeader }
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
            DNSHeader.Add(new DNSHeader(byteDNSHeader, (int)DNSHeaderSize));
        }
        #endregion
    }
}
