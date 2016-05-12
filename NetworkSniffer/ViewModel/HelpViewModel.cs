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
            try
            {
                MemoryStream memoryResStream = new MemoryStream(Encoding.Default.GetBytes(HelpResource.Help));

                HelpTextBox = new RichTextBox();
                HelpTextBox.Padding = new Thickness(5);
                HelpTextBox.SelectAll();
                HelpTextBox.Selection.Load(memoryResStream, DataFormats.Rtf);
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Document loading error");
            }
        }
        
        public RichTextBox HelpTextBox { get; private set; }
    }
}
