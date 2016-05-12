using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetworkSniffer.Model
{
    public class DNSHeader
    {
        #region Contructors
        public DNSHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            Identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Flags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Questions = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Answer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            AuthorityRR = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            AdditionalRR = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

        }
        #endregion

        #region Properties
        public ushort Identification { get; private set; }

        public ushort Flags { get; private set; } //Trebat stringirat i parsirat

        public ushort Questions { get; private set; }

        public ushort Answer { get; private set; }

        public ushort AuthorityRR { get; private set; }

        public ushort AdditionalRR{ get; private set; }
        #endregion
    }
}
