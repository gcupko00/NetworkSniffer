using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store ICMP header fields
    /// </summary>
    public class ICMPHeader
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of ICMPHeader class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing header data</param>
        /// <param name="length">Size of header in bytes</param>
        public ICMPHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            ICMPType = new ICMPType(binaryReader.ReadByte());

            Code = binaryReader.ReadByte();

            Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            RestOfHeader = IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());
        }
        #endregion

        #region Properties
        public ICMPType ICMPType { get; set; }

        public byte Code { get; set; }

        public short Checksum { get; set; }

        public int RestOfHeader { get; set; }
        #endregion
    }
}
