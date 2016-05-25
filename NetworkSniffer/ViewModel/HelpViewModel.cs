using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class contains properties that the Help View can data bind to.
    /// </summary>
    public class HelpViewModel : ViewModelBase
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of the HelpViewModel class
        /// </summary>
        public HelpViewModel()
        {
            GoToSourceRepository = new RelayCommand(() => GoToSourceRepositoryExecute());

            try
            {
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
        #endregion

        #region Properties
        /// <summary>
        /// Used to store help document
        /// </summary>
        public RichTextBox HelpTextBox { get; private set; }

        public ICommand GoToSourceRepository { get; set; }
        #endregion

        #region Methods
        /// <summary>
        /// Opens source code repository on GitHub in a default browser
        /// </summary>
        private void GoToSourceRepositoryExecute()
        {
            Process.Start("https://github.com/gcupko00/NetworkSniffer");
        }
        #endregion
    }
}
