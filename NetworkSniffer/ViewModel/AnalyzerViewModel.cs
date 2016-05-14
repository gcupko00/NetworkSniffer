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
        private DateTime startTime;

        public AnalyzerViewModel()
        {
            PacketLengthStats = StatsHandler.PacketLengthStats;

            TransportProtocolStats = StatsHandler.TransportProtocolStats;
            
            StatsHandler.Timer.Start();
            //testing
            startTime = StatsHandler.CaptureStartTime = DateTime.Now;

            StatsHandler.Timer.Elapsed += Timer_Elapsed;
        }

        private void Timer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            CapturingTime = (e.SignalTime - startTime).ToString().Substring(0, 12);
            PacketsTotal = StatsHandler.PacketsTotal;
            BytesTotal = StatsHandler.BytesTotal;
            AveragePPS = Math.Round((double)PacketsTotal / (e.SignalTime - startTime).Seconds, 3);
            AverageBPS = BytesTotal / (e.SignalTime - startTime).Seconds;
        }

        public ObservableCollection<PacketLengthCategory> PacketLengthStats { get; private set; }

        public ObservableCollection<TransportProtocolCategory> TransportProtocolStats { get; private set; }

        public string capturingTime;
        public string CapturingTime
        {
            get
            {
                return capturingTime;
            }
            set
            {
                capturingTime = value;
                RaisePropertyChanged("CapturingTime");
            }
        }

        private int packetsTotal;
        public int PacketsTotal
        {
            get
            {
                return packetsTotal;
            }
            set
            {
                packetsTotal = value;
                RaisePropertyChanged("PacketsTotal");
            }
        }

        private int bytesTotal;
        public int BytesTotal
        {
            get
            {
                return bytesTotal;
            }
            set
            {
                bytesTotal = value;
                RaisePropertyChanged("BytesTotal");
            }
        }

        private double averagePPS;
        public double AveragePPS
        {
            get
            {
                return averagePPS;
            }
            set
            {
                averagePPS = value;
                RaisePropertyChanged("AveragePPS");
            }
        }

        private int averageBPS;
        public int AverageBPS
        {
            get
            {
                return averageBPS;
            }
            set
            {
                averageBPS = value;
                RaisePropertyChanged("AverageBPS");
            }
        }
    }
}
