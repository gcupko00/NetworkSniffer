using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    public class DNSPacket
    {
        #region Members
        private const uint DNSHeaderSize = 12;
        private byte[] byteDNSHeader = new byte[DNSHeaderSize];
        private byte[] byteDNSMessage;
        #endregion

        #region Constructors
        public DNSPacket(byte[] byteBuffer, int length)
        {
            try
            {
                // Create MemoryStream out of received byte array
                // *check if it is possible to use MemoryStream(byteBuffer)
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                // Create BinaryReader out of MemoryStream
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // Copy header bytes from byteBuffer to byteDNSHeader
                Array.Copy(byteBuffer, byteDNSHeader, DNSHeaderSize);

                // Copy message data to byteDNSMessage
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
        public List<DNSHeader> DNSHeader { get; set; }

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
        private void PopulatePacketContents()
        {
            // Add header info
            DNSHeader.Add(new DNSHeader(byteDNSHeader, (int)DNSHeaderSize));
        }
        #endregion
    }
}
