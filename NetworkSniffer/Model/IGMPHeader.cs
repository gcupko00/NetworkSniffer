using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store IGMP header fields
    /// </summary>
    public class IGMPHeader
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of IGMPHeader class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing header data</param>
        /// <param name="length">Size of header in bytes</param>
        public IGMPHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            Type = binaryReader.ReadByte();

            MaxResponseTime = binaryReader.ReadByte();

            Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            GroupAddress = new IPAddress((uint)binaryReader.ReadInt32());
        }
        #endregion

        #region Properties
        public byte Type { get; set; }

        public byte MaxResponseTime { get; set; }

        public short Checksum { get; set; }

        public IPAddress GroupAddress { get; set; }
        #endregion
    }
}
