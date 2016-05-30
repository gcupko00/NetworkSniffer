using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to extract IGMP header
    /// </summary>
    public class IGMPPacket
    {
        #region Fields
        private const uint IGMPHeaderSize = 8;
        private byte[] byteIGMPHeader = new byte[IGMPHeaderSize];
        private byte[] byteIGMPMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of IGMPPacket class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing packet data</param>
        /// <param name="length">Packet size in bytes</param>
        public IGMPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                
                Array.Copy(byteBuffer, byteIGMPHeader, IGMPHeaderSize);
                
                byteIGMPMessage = new byte[length - IGMPHeaderSize];
                Array.Copy(byteBuffer, IGMPHeaderSize, byteIGMPMessage, 0, length - IGMPHeaderSize);

                IGMPHeader = new List<IGMPHeader>();

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
        /// Holds only one element - header part of the IGMPPacket
        /// </summary>
        public List<IGMPHeader> IGMPHeader { get; set; }

        /// <summary>
        /// Composite collection that stores header
        /// </summary>
        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = IGMPHeader }
                };
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Puts packet content in the PacketContent list
        /// Adds header info to IGMPHeader "list"
        /// </summary>
        private void PopulatePacketContents()
        {
            IGMPHeader.Add(new IGMPHeader(byteIGMPHeader, (int)IGMPHeaderSize));
        }
        #endregion
    }
}
