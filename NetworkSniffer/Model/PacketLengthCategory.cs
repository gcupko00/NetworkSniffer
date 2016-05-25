using System;
using System.ComponentModel;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to store a particular packet length range statistics
    /// </summary>
    public class PacketLengthCategory : INotifyPropertyChanged
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of PacketLengthCategory class
        /// </summary>
        /// <param name="range">Lowest and highest value as a string</param>
        public PacketLengthCategory(string range)
        {
            Range = range;
        }

        /// <summary>
        /// Initializes new instance of PacketLengthCategory class
        /// </summary>
        /// <param name="count">Number of packets with length in specified range</param>
        /// <param name="percentage">Percentage of packets with length in specified range</param>
        public PacketLengthCategory(int count, double percentage)
        {
            Count = count;
            Percentage = percentage;
        }

        /// <summary>
        /// Initializes new instance of PacketLengthCategory class
        /// </summary>
        /// <param name="range">Lowest and highest value as a string</param>
        /// <param name="count">Number of packets with length in specified range</param>
        /// <param name="percentage">Percentage of packets with length in specified range</param>
        public PacketLengthCategory(string range, int count, double percentage)
            : this(count, percentage)
        {
            Range = range;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Lowest and highest value as a string
        /// </summary>
        public string Range { get; set; }
                
        private int count;
        /// <summary>
        /// Number of packets with length in specified range
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
        /// Percentage of packets with length in specified range
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
