using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    public class UDPHeader
    {
        #region Contructors
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
