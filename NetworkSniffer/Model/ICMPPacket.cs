using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to extract ICMP header
    /// </summary>
    public class ICMPPacket
    {
        #region Members
        private const uint ICMPHeaderSize = 8;
        private byte[] byteICMPHeader = new byte[ICMPHeaderSize];
        private byte[] byteICMPMessage;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of ICMPPacket class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing packet data</param>
        /// <param name="length">Packet size in bytes</param>
        public ICMPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                
                Array.Copy(byteBuffer, byteICMPHeader, ICMPHeaderSize);
                
                byteICMPMessage = new byte[length - ICMPHeaderSize];
                Array.Copy(byteBuffer, ICMPHeaderSize, byteICMPMessage, 0, length - ICMPHeaderSize);

                ICMPHeader = new List<ICMPHeader>();

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
        /// Holds only one element - header part of the ICMPPacket
        /// </summary>
        public List<ICMPHeader> ICMPHeader { get; set; }

        /// <summary>
        /// Composite collection that stores header
        /// </summary>
        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = ICMPHeader }
                };
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Puts packet content in the PacketContent list
        /// Adds header info to ICMPHeader "list"
        /// </summary>
        private void PopulatePacketContents()
        {
            ICMPHeader.Add(new ICMPHeader(byteICMPHeader, (int)ICMPHeaderSize));
        }
        #endregion
    }
}
