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
        private byte[] byteTCPHeader;
        private byte[] byteTCPMessage;
        private const uint TCPHeaderSize = 20;
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

                PopulatePacketContents();
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        #region Properties
        public List<TCPHeader> TCPHeader { get; set; }

        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = TCPHeader }
                };
            }
        }
        #endregion

        #region Methods
        private void PopulatePacketContents()
        {
            // add header info
            TCPHeader.Add(new TCPHeader(byteTCPHeader, (int)TCPHeaderSize));
        }
        #endregion
    }
}
