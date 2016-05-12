using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System.Windows.Input;
using System.Collections.ObjectModel;
using System.Net;
using NetworkSniffer.Model;
using System.Net.Sockets;
using System;
using System.Windows;
using System.Windows.Data;
using System.Text;
using System.Windows.Documents;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class contains properties that the main View can data bind to.
    /// </summary>
    public class MainViewModel : ViewModelBase
    {
        #region Members
        private SnifferViewModel snifferViewModel = new SnifferViewModel();
        private AnalyzerViewModel analyzerViewModel = new AnalyzerViewModel();

        private InterfaceMonitor monitor;
        private readonly object packetListLock = new object();
        #endregion

        #region Constructors
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
            ClearPacketList = new RelayCommand(() => ClearPacketListExecute());
            ResetFilter = new RelayCommand(() => ResetFilterExecute());

            DeviceAddressList = new ObservableCollection<string>();
            PacketList = new ObservableCollection<IPPacket>();
            SelectedPacketTree = new ObservableCollection<IPPacket>();
            GetAddresses();
        }
        #endregion

        #region Properties
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

        private ObservableCollection<IPPacket> packetList;
        public ObservableCollection<IPPacket> PacketList
        {
            get
            {
                return packetList;
            }
            set
            {
                packetList = value;
                // Enables access to packetList from different threads
                BindingOperations.EnableCollectionSynchronization(packetList, packetListLock);
            }
        }

        // packet selected in listview
        private IPPacket selectedPacket;
        public IPPacket SelectedPacket
        {
            get
            {
                return selectedPacket;
            }
            set
            {
                selectedPacket = value;
                // There can be only one selected packet, so the list must be empty
                SelectedPacketTree.Clear();
                SelectedPacketTree.Add(selectedPacket);
                RaisePropertyChanged("SelectedPacket");
                RaisePropertyChanged("HexPacketData");
                RaisePropertyChanged("CharPacketData");
            }
        }

        // Since TreeView ItemsSource must be bound to the ObservableCollection, 
        // selected packet must be ObservableCollection 
        public ObservableCollection<IPPacket> SelectedPacketTree { get; private set; }

        public ObservableCollection<string> DeviceAddressList { get; private set; }

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

        public string HexPacketData
        {
            get
            {
                try
                {
                    int length = SelectedPacket.IPHeader[0].TotalLength;

                    StringBuilder stringBuilder = new StringBuilder(length * 2);

                    // Copy header and message from selected IP packet to packetData
                    byte[] packetData = new byte[length];
                    Array.Copy(SelectedPacket.ByteIPHeader, packetData, SelectedPacket.ByteIPHeader.Length);
                    Array.Copy(SelectedPacket.ByteIPMessage, 0, packetData, SelectedPacket.ByteIPHeader.Length, SelectedPacket.ByteIPMessage.Length);

                    for (int i = 0; i < length; i++)
                    {
                        stringBuilder.Append(packetData[i].ToString("x2") + " ");
                    }

                    return stringBuilder.ToString();
                }
                catch
                {
                    return null;
                }
            }
        }

        public string CharPacketData
        {
            get
            {
                try {
                    int length = SelectedPacket.IPHeader[0].TotalLength;

                    StringBuilder stringBuilder = new StringBuilder();

                    // Copy header and message from selected IP packet to packetData
                    byte[] packetData = new byte[length];
                    Array.Copy(SelectedPacket.ByteIPHeader, packetData, SelectedPacket.ByteIPHeader.Length);
                    Array.Copy(SelectedPacket.ByteIPMessage, 0, packetData, SelectedPacket.ByteIPHeader.Length, SelectedPacket.ByteIPMessage.Length);

                    for (int i = 0; i < length; i++)
                    {
                        if (packetData[i] > 31 && packetData[i] < 128)
                            stringBuilder.Append((char)packetData[i]);
                        else
                            stringBuilder.Append(".");
                    }

                    return stringBuilder.ToString();
                }
                catch
                {
                    return null;
                }
            }
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
                RaisePropertyChanged("Filter");
            }
        }
        #endregion

        #region Methods
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

        private void ReceiveNewPacket(IPPacket newPacket)
        {
            PacketList.Add(newPacket);
            newPacket.PacketID = (uint)PacketList.Count;
            //testing
            //IPAddress test = new IPAddress(newPacket.IPHeader[0].SourceIPAddress);
            //MessageBox.Show(newPacket.PacketID.ToString());
        }
        #endregion

        #region Commands
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
            else if (!UserIdentityHandler.IsUserAdministrator())
            {
                MessageBox.Show("Please start program with administrator privileges");
            }
            else
            {
                if (monitor == null ) {
                    monitor = new InterfaceMonitor(SelectedAddress);
                    monitor.newPacketEventHandler += new InterfaceMonitor.NewPacketEventHandler(ReceiveNewPacket);
                    monitor.StartCapture();

                    //testing
                    //MessageBox.Show("created monitor" + monitor.ToString());
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
                //MessageBox.Show("deleted monitor");
            }
        }

        public ICommand ClearPacketList { get; private set; }

        private void ClearPacketListExecute()
        {
            PacketList.Clear();
        }

        public ICommand ResetFilter { get; private set; }

        private void ResetFilterExecute()
        {
            Filter = "";
        }
        #endregion
    }
}