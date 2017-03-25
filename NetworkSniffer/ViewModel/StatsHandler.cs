using NetworkSniffer.Model;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Timers;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class conteins properties and methods to store and update traffic statistics
    /// </summary>
    public static class StatsHandler
    {
        #region Fields
        private const int MTU = 1024 * 64;
        #endregion

        #region Properties
        public static ObservableCollection<PacketLengthCategory> PacketLengthStats = new ObservableCollection<PacketLengthCategory>()
        {
            new PacketLengthCategory("40<"),
            new PacketLengthCategory("40-79"),
            new PacketLengthCategory("80-159"),
            new PacketLengthCategory("160-319"),
            new PacketLengthCategory("320-639"),
            new PacketLengthCategory("640-1279"),
            new PacketLengthCategory("1280-2559"),
            new PacketLengthCategory("2560-5119"),
            new PacketLengthCategory(">5119")
        };

        public static ObservableCollection<TransportProtocolCategory> TransportProtocolStats = new ObservableCollection<TransportProtocolCategory>()
        {
            new TransportProtocolCategory("TCP"),
            new TransportProtocolCategory("UDP"),
            new TransportProtocolCategory("ICMP"),
            new TransportProtocolCategory("IGMP"),
            new TransportProtocolCategory("Other"),
        };

        public static int PacketsTotal { get; set; }

        public static int BytesTotal { get; set; }
        
        public static Timer Timer = new Timer(1);

        public static Stopwatch StopWatch = new Stopwatch();
        #endregion

        #region Methods
        /// <summary>
        /// Updates traffic statistics according to the received packet characteristics
        /// </summary>
        /// <param name="newPacket">Received packet depending on which statistics are updated</param>
        public static void UpdateStats(IPPacket newPacket)
        {
            int newPacketLength = newPacket.IPHeader[0].TotalLength;
            string newPacketProtocol = newPacket.IPHeader[0].TransportProtocolName;

            PacketsTotal++;
            BytesTotal += newPacket.IPHeader[0].TotalLength;

            SortPacketByLength(newPacketLength);
            SortPacketByProtocol(newPacketProtocol);
        }

        /// <summary>
        /// Resets all statistics
        /// </summary>
        public static void ResetStats()
        {
            StopWatch.Reset();
            PacketsTotal = 0;
            BytesTotal = 0;

            foreach(PacketLengthCategory plc in PacketLengthStats)
            {
                plc.Count = 0;
                plc.Percentage = 0;
            }

            foreach(TransportProtocolCategory tpc in TransportProtocolStats)
            {
                tpc.Count = 0;
                tpc.Percentage = 0;
            }
        }

        private static void SortPacketByLength(int newPacketLength)
        {
            if (newPacketLength < 40)
            {
                PacketLengthStats[0].Count++;
                PacketLengthStats[0].Percentage = (double)PacketLengthStats[0].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 80)
            {
                PacketLengthStats[1].Count++;
                PacketLengthStats[1].Percentage = (double)PacketLengthStats[1].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 160)
            {
                PacketLengthStats[2].Count++;
                PacketLengthStats[2].Percentage = (double)PacketLengthStats[2].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 320)
            {
                PacketLengthStats[3].Count++;
                PacketLengthStats[3].Percentage = (double)PacketLengthStats[3].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 640)
            {
                PacketLengthStats[4].Count++;
                PacketLengthStats[4].Percentage = (double)PacketLengthStats[4].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 1280)
            {
                PacketLengthStats[5].Count++;
                PacketLengthStats[5].Percentage = (double)PacketLengthStats[5].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 2560)
            {
                PacketLengthStats[6].Count++;
                PacketLengthStats[6].Percentage = (double)PacketLengthStats[6].Count / PacketsTotal * 100;
            }
            else if (newPacketLength < 5120)
            {
                PacketLengthStats[7].Count++;
                PacketLengthStats[7].Percentage = (double)PacketLengthStats[7].Count / PacketsTotal * 100;
            }
            else
            {
                PacketLengthStats[8].Count++;
                PacketLengthStats[8].Percentage = (double)PacketLengthStats[8].Count / PacketsTotal * 100;
            }
        }

        private static void SortPacketByProtocol(string newPacketProtocolName)
        {
            if (newPacketProtocolName == "TCP")
            {
                TransportProtocolStats[0].Count++;
                TransportProtocolStats[0].Percentage = (double)TransportProtocolStats[0].Count / PacketsTotal * 100;
            }
            else if (newPacketProtocolName == "UDP")
            {
                TransportProtocolStats[1].Count++;
                TransportProtocolStats[1].Percentage = (double)TransportProtocolStats[1].Count / PacketsTotal * 100;
            }
            else if (newPacketProtocolName == "ICMP")
            {
                TransportProtocolStats[2].Count++;
                TransportProtocolStats[2].Percentage = (double)TransportProtocolStats[2].Count / PacketsTotal * 100;
            }
            else if (newPacketProtocolName == "IGMP")
            {
                TransportProtocolStats[3].Count++;
                TransportProtocolStats[3].Percentage = (double)TransportProtocolStats[3].Count / PacketsTotal * 100;
            }
            else
            {
                TransportProtocolStats[4].Count++;
                TransportProtocolStats[4].Percentage = (double)TransportProtocolStats[4].Count / PacketsTotal * 100;
            }
        }
        #endregion
    }
}
