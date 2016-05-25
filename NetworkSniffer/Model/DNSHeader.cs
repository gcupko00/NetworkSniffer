using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store DNS header fields
    /// </summary>
    public class DNSHeader
    {
        #region Contructors
        /// <summary>
        /// Initializes new instance of DNSHeader class
        /// </summary>
        /// <param name="byteBuffer">Header data to be parsed</param>
        /// <param name="length">Header length</param>
        public DNSHeader(byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            Identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            uShortFlags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Questions = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            Answer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            AuthorityRR = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            AdditionalRR = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
        }
        #endregion

        #region Properties
        public ushort Identification { get; private set; }

        public ushort uShortFlags { get; private set; }

        // Flags does not provide info about Opcode and Rcode
        public string Flags
        {
            get
            {
                string value = "(";

                if ((uShortFlags & 0x10) != 0)
                {
                    value += "CD, ";
                }
                if ((uShortFlags & 0x20) != 0)
                {
                    value += "AD, ";
                }
                if ((uShortFlags & 0x40) != 0)
                {
                    value += "Z, ";
                }
                if ((uShortFlags & 0x80) != 0)
                {
                    value += "RA, ";
                }
                if ((uShortFlags & 0x100) != 0)
                {
                    value += "RD, ";
                }
                if ((uShortFlags & 0x200) != 0)
                {
                    value += "TC, ";
                }
                if ((uShortFlags & 0x400) != 0)
                {
                    value += "AA, ";
                }
                if ((uShortFlags & 0x8000) != 0)
                {
                    value += "QR";
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

        public ushort Questions { get; private set; }

        public ushort Answer { get; private set; }

        public ushort AuthorityRR { get; private set; }

        public ushort AdditionalRR { get; private set; }
        #endregion
    }
}
