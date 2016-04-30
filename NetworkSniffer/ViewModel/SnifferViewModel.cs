using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System.Windows.Input;

namespace NetworkSniffer.ViewModel
{
    public class SnifferViewModel : ViewModelBase
    {
        public SnifferViewModel()
        {

        }

        private string filter;

        public string Filter
        {
            get
            {
                return filter;
            }
            set
            {
                filter = value;
            }
        }

        public ICommand StartCapture { get; private set; }

        public ICommand StopCapture { get; private set; }


    }
}
