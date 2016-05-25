using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store TCP header fields
    /// </summary>
    public class TCPHeader
    {
        #region Contructors
        /// <summary>
        /// Initializes new instance of TCPHeader class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing header data</param>
        /// <param name="length">Size of header in bytes</param>
        public TCPHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            SourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            DestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            SequenceNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            AcknowledgmentNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            ReservedAndFlags  = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            DataOffset = (byte)(ReservedAndFlags >> 8);
            DataOffset >>= 1;
            DataOffset <<= 1;

            WindowSize = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
        }
        #endregion

        #region Properties
        public ushort SourcePort { get; set; }

        public ushort DestinationPort { get; set; }

        public uint SequenceNumber { get; set; }

        public uint AcknowledgmentNumber { get; set; }

        public byte DataOffset { get; set; }

        public ushort ReservedAndFlags { get; set; }
        
        public string Flags
        {
            get
            {
                string value = "(";

                if ((ReservedAndFlags & 0x01) != 0)
                {
                    value += "FIN, ";
                }
                if ((ReservedAndFlags & 0x02) != 0)
                {
                    value += "SYN, ";
                }
                if ((ReservedAndFlags & 0x04) != 0)
                {
                    value += "RST, ";
                }
                if ((ReservedAndFlags & 0x08) != 0)
                {
                    value += "PSH, ";
                }
                if ((ReservedAndFlags & 0x10) != 0)
                {
                    value += "ACK, ";
                }
                if ((ReservedAndFlags & 0x20) != 0)
                {
                    value += "URG";
                }
                value += ")";

                if (value == "()")
                {
                    value = "";
                }
                else if (value.Contains(", )"))
                {
                    value = value.Remove(value.Length - 3, 2);
                }

                return value;
            }
        }

        public ushort WindowSize { get; set; }

        public short Checksum { get; set; }

        public ushort UrgentPointer { get; set; }
        #endregion
    }
}
