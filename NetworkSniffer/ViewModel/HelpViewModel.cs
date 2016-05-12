using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using System.Windows.Controls;
using System.Windows.Documents;
using System.IO;
using System.Windows;

namespace NetworkSniffer.ViewModel
{
    public class HelpViewModel : ViewModelBase
    {
        public HelpViewModel()
        {
            FlowDocument helpDocument = Application.LoadComponent(new Uri("/Resources/Help.rtf", UriKind.RelativeOrAbsolute)) as FlowDocument;

            HelpTextBox = new RichTextBox();

            HelpTextBox.Document = helpDocument;
        }
        
        public RichTextBox HelpTextBox { get; private set; }
    }
}
