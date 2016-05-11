using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using System.Windows.Data;
using System.IO;

namespace NetworkSniffer.Model
{
    public class TCPPacket
    {
        #region Members
        private byte[] byteTCPHeader;
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


            }
            catch
            {

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
    }
}
