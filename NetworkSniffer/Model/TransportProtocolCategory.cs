using System;
using System.ComponentModel;

namespace NetworkSniffer
{
    /// <summary>
    /// This class is used to store a particular transport protocol statistics
    /// </summary>
    public class TransportProtocolCategory : INotifyPropertyChanged
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of TransportProtocolCategory class
        /// </summary>
        /// <param name="protocolName">Name of protocol category</param>
        public TransportProtocolCategory(string protocolName)
        {
            ProtocolName = protocolName;
        }

        /// <summary>
        /// Initializes new instance of TransportProtocolCategory class
        /// </summary>
        /// <param name="count">Number of packets containing transport packets that use specified protocol</param>
        /// <param name="percentage">Percentage of packets containing transport packets that use specified protocol</param>
        public TransportProtocolCategory(int count, double percentage)
        {
            Count = count;
            Percentage = percentage;
        }

        /// <summary>
        /// Initializes new instance of TransportProtocolCategory class
        /// </summary>
        /// <param name="protocolName">Name of protocol category</param>
        /// <param name="count">Number of packets containing transport packets that use specified protocol</param>
        /// <param name="percentage">Percentage of packets containing transport packets that use specified protocol</param>
        public TransportProtocolCategory(string protocolName, int count, double percentage)
            : this(count, percentage)
        {
            ProtocolName = protocolName;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Name of protocol category
        /// </summary>
        public string ProtocolName { get; set; }

        private int count;
        /// <summary>
        /// Number of packets containing transport packets that use specified protocol
        /// </summary>
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
        /// <summary>
        /// Percentage of packets containing transport packets that use specified protocol
        /// </summary>
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
