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
        private byte[] byteUDPHeader;
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
                Array.Copy(byteBuffer, byteUDPHeader, 8);

                // Copy message data to byteUDPMessage
                byteUDPMessage = new byte[length - 8];
                Array.Copy(byteBuffer, 8, byteUDPMessage, 0, length - 8);

                UDPHeader = new List<UDPHeader>();

                PopulatePacketContents();
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        public List<UDPHeader> UDPHeader { get; set; }

        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = UDPHeader }
                };
            }
        }
        #endregion

        #region Methods
        private void PopulatePacketContents()
        {
            // add header info
            UDPHeader.Add(new UDPHeader(byteUDPHeader, 8));
        }
        #endregion
    }
}
