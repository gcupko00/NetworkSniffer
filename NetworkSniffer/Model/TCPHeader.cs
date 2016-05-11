using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetworkSniffer.Model
{
    public class TCPHeader
    {
        #region Contructors
        public TCPHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            SourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            SequenceNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            AckknowledgmentNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            ReservedAndFlags  = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            DataOffset = (byte)(ReservedAndFlags >> 8);
            DataOffset >>= 1;
            DataOffset <<= 1;

            WindowSize = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadUInt16());

            Checksum = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadUInt16());

            UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadUInt16()); 

            // *options
        }
        #endregion

        #region Properties
        public ushort SourcePort { get; set; }

        public ushort DestinationPort { get; set; }

        public uint SequenceNumber { get; set; }

        public uint AckknowledgmentNumber { get; set; }

        public byte DataOffset { get; set; }

        public ushort ReservedAndFlags { get; set; }

        public ushort WindowSize { get; set; }

        public ushort Checksum { get; set; }

        public ushort UrgentPointer { get; set; }
        #endregion
    }
}
