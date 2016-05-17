using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store UDP header fields
    /// </summary>
    public class UDPHeader
    {
        #region Contructors
        /// <summary>
        /// Initializes new instance of UDPHeader class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing header data</param>
        /// <param name="length">Size of header in bytes</param>
        public UDPHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            SourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Length = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
        }
        #endregion

        #region Properties
        public ushort SourcePort { get; set; }

        public ushort DestinationPort { get; set; }

        public ushort Length { get; set; }

        public short Checksum { get; set; }
        #endregion
    }
}
