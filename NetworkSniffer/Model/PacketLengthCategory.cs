using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;

namespace NetworkSniffer.Model
{
    public class PacketLengthCategory : INotifyPropertyChanged
    {
        #region Constructors
        public PacketLengthCategory(string range)
        {
            Range = range;
        }

        public PacketLengthCategory(int count, double percentage)
        {
            Count = count;
            Percentage = percentage;
        }

        public PacketLengthCategory(string range, int count, double percentage)
            : this(count, percentage)
        {
            Range = range;
        }
        #endregion

        #region Properties
        public string Range { get; set; }

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
