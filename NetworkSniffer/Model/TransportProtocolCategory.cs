using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;

namespace NetworkSniffer
{
    public class TransportProtocolCategory : INotifyPropertyChanged
    {
        #region Constructors
        public TransportProtocolCategory(string protocolName)
        {
            ProtocolName = protocolName;
        }

        public TransportProtocolCategory(int count, double percentage)
        {
            Count = count;
            Percentage = percentage;
        }

        public TransportProtocolCategory(string protocolName, int count, double percentage)
            : this(count, percentage)
        {
            ProtocolName = protocolName;
        }
        #endregion

        #region Properties
        public string ProtocolName { get; set; }

        private int count;
        public int Count
        {
            get
            {
                return count;
            }
            set
            {
                count = value;
                NotifyPropertyChanged("Count");
            }
        }

        private double percentage;
        public double Percentage
        {
            get
            {
                return percentage;
            }
            set
            {
                percentage = Math.Round(value, 3);
                NotifyPropertyChanged("Percentage");
            }
        }
        #endregion

        #region Event handlers
        public event PropertyChangedEventHandler PropertyChanged;

        private void NotifyPropertyChanged(string propertyName)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }
        #endregion
    }
}
