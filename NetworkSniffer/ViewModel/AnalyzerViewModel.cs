using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using NetworkSniffer.Model;

namespace NetworkSniffer.ViewModel
{
    public class AnalyzerViewModel : ViewModelBase
    {
        public AnalyzerViewModel()
        {
            PacketLengthStats = StatsHandler.PacketLengthStats;

            TransportProtocolStats = StatsHandler.TransportProtocolStats;
        }

        public ObservableCollection<PacketLengthCategory> PacketLengthStats { get; private set; }

        public ObservableCollection<TransportProtocolCategory> TransportProtocolStats { get; private set; }
    }
}
