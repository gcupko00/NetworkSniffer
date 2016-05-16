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
    /// <summary>
    /// This class contains properties that the HelpView can data bind to.
    /// </summary>
    public class HelpViewModel : ViewModelBase
    {
        /// <summary>
        /// Initializes new instance of the HelpViewModel class
        /// </summary>
        public HelpViewModel()
        {
            try
            {
                // Stores help document as memory stream
                MemoryStream memoryResStream = new MemoryStream(Encoding.Default.GetBytes(HelpResource.Help));

                HelpTextBox = new RichTextBox();
                HelpTextBox.IsReadOnly = true;
                HelpTextBox.Padding = new Thickness(5);
                HelpTextBox.SelectAll();
                HelpTextBox.Selection.Load(memoryResStream, DataFormats.Rtf);
            }
            catch
            {
                return;
            }
        }
        
        /// <summary>
        /// Used to store help document
        /// </summary>
        public RichTextBox HelpTextBox { get; private set; }
    }
}
