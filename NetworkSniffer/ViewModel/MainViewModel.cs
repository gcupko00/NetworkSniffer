using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System.Windows.Input;
using System.Collections.ObjectModel;
using System.Net;
using NetworkSniffer.Model;
using System.Security.Principal;
using System.Net.Sockets;
using System;
using System.Windows;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class contains properties that the main View can data bind to.
    /// </summary>
    public class MainViewModel : ViewModelBase
    {
        private SnifferViewModel snifferViewModel = new SnifferViewModel();
        private AnalyzerViewModel analyzerViewModel = new AnalyzerViewModel();

        private InterfaceMonitor monitor;
        /// <summary>
        /// Initializes a new instance of the MainViewModel class.
        /// </summary>
        public MainViewModel()
        {
            CurrentViewModel = snifferViewModel;
            OpenAnalyzer = new RelayCommand(() => OpenAnalyzerExecute());
            OpenSniffer = new RelayCommand(() => OpenSnifferExecute());
            StartCapture = new RelayCommand(() => StartCaptureExecute());
            StopCapture = new RelayCommand(() => StopCaputureExecute());

            DeviceAddressList = new ObservableCollection<string>();
            GetAddresses();
        }

        private ViewModelBase currentViewModel;
        public ViewModelBase CurrentViewModel
        {
            get
            {
                return currentViewModel;
            }
            set
            {
                currentViewModel = value;
                RaisePropertyChanged("CurrentViewModel");
            }
        }

        private ObservableCollection<string> deviceAddressList;
        public ObservableCollection<string> DeviceAddressList
        {
            get
            {
                return deviceAddressList;
            }
            private set
            {
                deviceAddressList = value;
                RaisePropertyChanged("DeviceAddressList");
            }
        }

        private string selectedAddress;
        public string SelectedAddress
        {
            get
            {
                return selectedAddress;
            }
            set
            {
                selectedAddress = value;
                RaisePropertyChanged("SelectedAddress");
            }
        }

        private void GetAddresses()
        {
            IPHostEntry HostEntry = Dns.GetHostEntry(Dns.GetHostName());
            if (HostEntry.AddressList.Length > 0) {
                foreach (IPAddress ip in HostEntry.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        DeviceAddressList.Add(ip.ToString());
                    }
                }
            }
        }

        public ICommand OpenAnalyzer { get; private set; }
        
        private void OpenAnalyzerExecute()
        {
            CurrentViewModel = analyzerViewModel;
        }

        public ICommand OpenSniffer { get; private set; }

        private void OpenSnifferExecute()
        {
            CurrentViewModel = snifferViewModel;
        }
        
        public ICommand StartCapture { get; private set; }

        private void StartCaptureExecute()
        {
            if (SelectedAddress == "" || SelectedAddress == null)
            {
                MessageBox.Show("Please select device address");
            }
            else if (!IsUserAdministrator())
            {
                MessageBox.Show("Please start program with administrator privileges");
            }
            else
            {
                if (monitor == null ) {
                    monitor = new InterfaceMonitor(SelectedAddress);

                    //testing
                    MessageBox.Show("created monitro" + monitor.ToString());
                }
            }
        }

        public ICommand StopCapture { get; private set; }

        private void StopCaputureExecute()
        {
            if (monitor != null)
            {
                monitor.StopCapture();
                monitor = null;

                //testing
                MessageBox.Show("deleted monitor");
            }
        }

        // Ovo bi trebalo ubacit u neku klasu. cili ovaj kod je organizirani kaos
        public bool IsUserAdministrator()
        {
            bool isAdmin;
            WindowsIdentity user = null;
            try
            {
                //get the currently logged in user
                user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            finally
            {
                if (user != null)
                    user.Dispose();
            }
            return isAdmin;
        }
    }
}