using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Microsoft.VisualBasic;
using NetworkSniffer.Model;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Drawing;

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
        private HelpViewModel helpViewModel = new HelpViewModel();

        private InterfaceMonitor monitor;
        private string filter;
        private readonly object packetListLock = new object();
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the MainViewModel class.
        /// </summary>
        public MainViewModel()
        {
            filter = "";
            CurrentViewModel = snifferViewModel;
            OpenAnalyzer = new RelayCommand(() => OpenAnalyzerExecute());
            OpenSniffer = new RelayCommand(() => OpenSnifferExecute());
            OpenHelp = new RelayCommand(() => OpenHelpExecute());
            StartCapture = new RelayCommand(() => StartCaptureExecute());
            StopCapture = new RelayCommand(() => StopCaputureExecute());
            ClearPacketList = new RelayCommand(() => ClearPacketListExecute());
            ResetFilter = new RelayCommand(() => ResetFilterExecute());
            ApplyFilter = new RelayCommand(() => ApplyFilterExecute());
            RefreshDeviceAddressList = new RelayCommand(() => RefreshDeviceAddressListExecute());

            DeviceAddressList = new ObservableCollection<string>();
            PacketList = new ObservableCollection<IPPacket>();
            FilteredPacketList = new ObservableCollection<IPPacket>();
            SelectedPacketTree = new ObservableCollection<IPPacket>();
            GetAddresses();
        }
        #endregion

        #region Properties
        private ViewModelBase currentViewModel;
        /// <summary>
        /// Viewmodel for currently displayed view
        /// </summary>
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
        /// <summary>
        /// Stores all captured packets
        /// </summary>
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
        
        private ObservableCollection<IPPacket> filteredPacketList;
        /// <summary>
        /// Stores packets from PacketList filtered according to filter conditions
        /// </summary>
        public ObservableCollection<IPPacket> FilteredPacketList
        {
            get
            {
                return filteredPacketList;
            }
            set
            {
                filteredPacketList = value;
                // Enables access to packetList from different threads
                BindingOperations.EnableCollectionSynchronization(filteredPacketList, packetListLock);
            }
        }
        
        private IPPacket selectedPacket;
        /// <summary>
        /// Packet currently selected in FilteredPacketList
        /// </summary>
        public IPPacket SelectedPacket
        {
            get
            {
                return selectedPacket;
            }
            set
            {
                selectedPacket = value;
                GetPacketHexAndCharData();
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
        /// <summary>
        /// Used to bind TreeViewItems to SelectedPacket properties
        /// </summary>
        public ObservableCollection<IPPacket> SelectedPacketTree { get; private set; }

        /// <summary>
        /// List of available network interfaces addresses
        /// </summary>
        public ObservableCollection<string> DeviceAddressList { get; private set; }

        private string selectedAddress;
        /// <summary>
        /// Currently selected IP address of an interface on which packets are being captured
        /// </summary>
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

        private string hexPacketData;
        /// <summary>
        /// Selected IP packet data in hexadecimal notation
        /// </summary>
        public string HexPacketData
        {
            get
            {
                return hexPacketData;
            }
            set
            {
                hexPacketData = value;
                RaisePropertyChanged("HexPacketData");
            }
        }

        private string charPacketData;
        /// <summary>
        /// Selected IP packet data in ASCII character notation
        /// </summary>
        public string CharPacketData
        {
            get
            {
                return charPacketData;
            }
            set
            {
                charPacketData = value;
                RaisePropertyChanged("CharPacketData");
            }
        }

        private string filterBox;
        /// <summary>
        /// Filter conditions used to fill FilteredPacketsList
        /// </summary>
        public string FilterBox
        {
            get
            {
                return filterBox;
            }
            set
            {
                filterBox = value;
                IsResetEnabled = true;
                IsFilterEnabled = true;
                if (string.Equals(filterBox, filter))
                {
                    IsFilterEnabled = false;
                }
                else
                {
                    IsFilterEnabled = true;
                }
                FilterValidity = "Transparent";

                RaisePropertyChanged("FilterBox");
            }
        }

        private bool isInterfaceChangeAllowed = true;
        /// <summary>
        /// Used to enable/disable capture interface change
        /// </summary>
        public bool IsInterfaceChangeAllowed
        {
            get
            {
                return isInterfaceChangeAllowed;
            }
            set
            {
                isInterfaceChangeAllowed = value;
                RaisePropertyChanged("IsInterfaceChangeAllowed");
            }
        }

        private bool isStartEnabled = true;
        /// <summary>
        /// Used to enable/disable capture start
        /// </summary>
        public bool IsStartEnabled
        {
            get
            {
                return isStartEnabled;
            }
            set
            {
                isStartEnabled = value;
                RaisePropertyChanged("IsStartEnabled");
            }
        }

        private bool isStopEnabled = false;
        /// <summary>
        /// Used to enable/disable capture start
        /// </summary>
        public bool IsStopEnabled
        {
            get
            {
                return isStopEnabled;
            }
            set
            {
                isStopEnabled = value;
                RaisePropertyChanged("IsStopEnabled");
            }
        }

        private bool isClearEnabled = false;
        /// <summary>
        /// Used to enable/disable clear button
        /// </summary>
        public bool IsClearEnabled
        {
            get
            {
                return isClearEnabled;
            }
            set
            {
                isClearEnabled = value;
                RaisePropertyChanged("IsClearEnabled");
            }
        }

        private bool isResetEnabled = false;
        /// <summary>
        /// Used to enable/disable reset button
        /// </summary>
        public bool IsResetEnabled
        {
            get
            {
                return isResetEnabled;
            }
            set
            {
                isResetEnabled = value;
                RaisePropertyChanged("IsResetEnabled");
            }
        }

        private bool isFilterEnabled = false;
        /// <summary>
        /// Used to enable/disable filter button
        /// </summary>
        public bool IsFilterEnabled
        {
            get
            {
                return isFilterEnabled;
            }
            set
            {
                isFilterEnabled = value;
                RaisePropertyChanged("IsFilterEnabled");
            }
        }

        private string filterValidity;
        public string FilterValidity
        {
            get
            {
                return filterValidity;
            }
            set
            {
                filterValidity = value;
                RaisePropertyChanged("FilterValidity");
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets IP addresses of all available hosts
        /// </summary>
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

            if (DeviceAddressList.Count > 0)
            {
                SelectedAddress = DeviceAddressList[0];
            }
        }        

        /// <summary>
        /// Adds newly received packet to packet lists
        /// </summary>
        /// <param name="newPacket">Packet to be added to packet lists</param>
        private void ReceiveNewPacket(IPPacket newPacket)
        {
            newPacket.PacketID = (uint)PacketList.Count + 1;

            lock (PacketList)
            {
                PacketList.Add(newPacket);
            }
            IsClearEnabled = true;

            lock (filteredPacketList)
            {
                AddToFilteredList(newPacket);
            }

            StatsHandler.UpdateStats(newPacket);
        }

        /// <summary>
        /// Decides whether newPacket should be added to FilteredPacketList or not
        /// </summary>
        /// <param name="newPacket">Packet to be processed and added to FilteredPacketList if it satisfies filter conditions</param>
        private void AddToFilteredList(IPPacket newPacket)
        {
            // If the filterString is empty, just add newPacket to the FilterPacketList
            // and set filter validity to default since there is no filter
            if (string.IsNullOrEmpty(filter))
            {
                FilteredPacketList.Add(newPacket);
                FilterValidity = "Transparent";
                return;
            }

            // Split filter into substrings and make it all uppercase
            List<string> filterList = new List<string>(filter.ToUpper().Split(' '));

            // List of IP addresses from src/dest syntax
            List<string> SrcIPList = new List<string>();
            List<string> DestIPList = new List<string>();

            // List of Ports from sp/dp syntax
            List<string> SrcPortList = new List<string>();
            List<string> DestPortList = new List<string>();

            // List of Lengths from length>/length< syntax
            List<string> HigherLengthList = new List<string>();
            List<string> LowerLengthList = new List<string>();

            // A list of allowed filters
            string[] allowedProtocols = { "UDP", "TCP", "IGMP", "ICMP", "DNS" };
            // After cleaning all the garbage, filterList should contain only strings
            // from allowedProtocols

            // Remove all substrings that are not in list of allowed filters
            // But if a substring is src/dest ip or sp/dp port, tranfser it to its List
            for (int i = filterList.Count - 1; i >= 0; i--)
            {
                // Next two If conditions will add IP addresses to IP Lists, if there are any
                if (filterList[i].Contains("SRC="))
                {
                    SrcIPList = ValidIPAddress(SrcIPList, filterList[i]);
                }
                else if (filterList[i].Contains("DEST="))
                {
                    DestIPList = ValidIPAddress(DestIPList, filterList[i]);
                }

                // Next two If conditions will add Ports to Port Lists, if there are any
                else if (filterList[i].Contains("SP="))
                {
                    SrcPortList = ValidPort(SrcPortList, filterList[i]);
                }
                else if (filterList[i].Contains("DP="))
                {
                    DestPortList = ValidPort(DestPortList, filterList[i]);
                }

                // Next two If conditions will add Length to Length Lists, if there are any
                else if (filterList[i].Contains("LENGTH>"))
                {
                    HigherLengthList = ValidIPLength(HigherLengthList, filterList[i]);
                }
                else if (filterList[i].Contains("LENGTH<"))
                {
                    LowerLengthList = ValidIPLength(LowerLengthList, filterList[i]);
                }

                // This else keeps only allowedProtocols in filterList
                else
                {
                    // If substring is a protocol from AllowedProtocol list,
                    // don't remove it and continue
                    string[] check = Strings.Filter(allowedProtocols, filterList[i], true);
                    if (check != null && check.Length > 0)
                    {
                        continue;
                    }
                }
                // Cleaning the garbage
                filterList.RemoveAt(i);
            }

            // If none of the substrings uses the proper syntax, ignore it and add packet
            // as if there was no filter at all. Filter is not valid so paint it red.
            if (filterList.Count == 0 && SrcIPList.Count == 0 && DestIPList.Count == 0 &&
                SrcPortList.Count == 0 && DestPortList.Count == 0 &&
                HigherLengthList.Count == 0 && LowerLengthList.Count == 0)
            {
                FilteredPacketList.Add(newPacket);
                FilterValidity = "LightSalmon";
                return;
            }
            // Else filter is valid
            else
            {
                FilterValidity = "LightGreen";
            }

            bool ProtocolRule = true;
            foreach (string filterString in filterList)
            {
                ProtocolRule = false;
                if (filterString.Equals("UDP") && newPacket.UDPPacket.Count > 0)
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("TCP") && newPacket.TCPPacket.Count > 0)
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("IGMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "IGMP")
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("ICMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "ICMP")
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("DNS") && 
                    newPacket.UDPPacket.Count > 0 &&
                    (newPacket.UDPPacket[0].UDPHeader[0].DestinationPort == 53 ||
                    newPacket.UDPPacket[0].UDPHeader[0].SourcePort == 53))
                {
                    ProtocolRule = true;
                    break;
                }
            }

            bool SrcIPRule = true;
            foreach (string ip in SrcIPList)
            {
                SrcIPRule = false;
                if (ip == newPacket.IPHeader[0].SourceIPAddress.ToString())
                {
                    SrcIPRule = true;
                    break;
                }
            }

            bool DstIPRule = true;
            foreach (string ip in DestIPList)
            {
                DstIPRule = false;
                if (ip == newPacket.IPHeader[0].DestinationIpAddress.ToString())
                {
                    DstIPRule = true;
                    break;
                }
            }

            bool SrcPortRule = true;
            foreach (string port in SrcPortList)
            {
                SrcPortRule = false;
                if (newPacket.TCPPacket.Count > 0 &&
                    port == newPacket.TCPPacket[0].TCPHeader[0].SourcePort.ToString())
                {
                    SrcPortRule = true;
                    break;
                }
                else if (newPacket.UDPPacket.Count > 0 &&
                         port == newPacket.UDPPacket[0].UDPHeader[0].SourcePort.ToString()) 
                {
                    SrcPortRule = true;
                    break;
                }
            }

            bool DestPortRule = true;
            foreach (string port in DestPortList)
            {
                DestPortRule = false;
                if (newPacket.TCPPacket.Count > 0 &&
                    port == newPacket.TCPPacket[0].TCPHeader[0].DestinationPort.ToString())
                {
                    DestPortRule = true;
                    break;
                }
                else if (newPacket.UDPPacket.Count > 0 &&
                         port == newPacket.UDPPacket[0].UDPHeader[0].DestinationPort.ToString()) 
                {
                    DestPortRule = true;
                    break;
                }
            }

            bool LowerLengthRule = true;
            ushort packetLength = newPacket.IPHeader[0].TotalLength;
            foreach (string LowerLength in LowerLengthList)
            {
                LowerLengthRule = false;
                ushort lowerLenght = ushort.Parse(LowerLength);
                
                if (lowerLenght > packetLength)
                {
                    LowerLengthRule = true;
                    break;
                }
            }

            bool HigherLengthRule = true;
            foreach (string HigherLength in HigherLengthList)
            {
                HigherLengthRule = false;
                ushort higherLenght = ushort.Parse(HigherLength);
                
                if (higherLenght < packetLength)
                {
                    HigherLengthRule = true;
                    break;
                }
            }

            // If newPacket satisfies all the filter rules, add it to filteredPacketList
            if (ProtocolRule == true && SrcIPRule == true && DstIPRule == true &&
                SrcPortRule == true && DestPortRule == true && LowerLengthRule == true &&
                HigherLengthRule == true)
            {
                FilteredPacketList.Add(newPacket);
            }            
        }

        /// <summary>
        /// Returns the same List given in parameter list, but with new string
        /// if evaluated as valid
        /// </summary>
        /// <param name="IPList">List of IPs in which new IP will be stored</param>
        /// <param name="isValid">IP to be evaluated</param> 
        private List<string> ValidIPAddress(List<string> IPList, string isValid)
        {
            const string PatternIP = @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$";
            const string SrcPattern = @"^SRC=" + PatternIP;
            const string DstPattern = @"^DEST=" + PatternIP;

            if (Regex.Match(isValid, SrcPattern).Success ||
                Regex.Match(isValid, DstPattern).Success)
            {
                string ipString = Regex.Match(isValid, PatternIP).Value;
                IPAddress ipAddress;
                if (IPAddress.TryParse(ipString, out ipAddress))
                {
                    IPList.Add(ipString);
                }
            }

            return IPList;
        }

        /// <summary>
        /// Returns the same List given in parameter list, but with new string
        /// if evaluated as valid
        /// </summary>
        /// <param name="PortList">List of Ports in which new Port will be stored</param>
        /// <param name="isValid">Port to be evaluated</param> 
        private List<string> ValidPort(List<string> PortList, string isValid)
        {
            const string PatternPort = @"\d{1,5}$";
            const string SrcPattern = @"^SP=" + PatternPort;
            const string DstPattern = @"^DP=" + PatternPort;

            if (Regex.Match(isValid, SrcPattern).Success ||
                Regex.Match(isValid, DstPattern).Success)
            {
                string PortString = Regex.Match(isValid, PatternPort).Value;
                ushort usPort;
                if (ushort.TryParse(PortString, out usPort))
                {
                    PortList.Add(PortString);
                }
            }

            return PortList;
        }

        /// <summary>
        /// Returns the same List given in parameter list, but with new string
        /// if evaluated as valid
        /// </summary>
        /// <param name="LengthIPList">List of Lengths in which new Length will be stored</param>
        /// <param name="isValid">Length to be evaluated</param> 
        private List<string> ValidIPLength(List<string> LengthIPList, string isValid)
        {
            const string PatternLength = @"\d{1,5}$";
            const string LowerPattern = @"^LENGTH<" + PatternLength;
            const string HigherPattern = @"^LENGTH>" + PatternLength;

            bool HigherBool = Regex.Match(isValid, HigherPattern).Success;
            bool LowerBool = Regex.Match(isValid, LowerPattern).Success;
            if (HigherBool || LowerBool)
            {
                string LengthString = Regex.Match(isValid, PatternLength).Value;
                ushort IPLength;

                // We actually store only one value per list, for example in "length>40 length>30"
                // we only need tostore 40 in the list, because storing 30 is unnecessary
                if (ushort.TryParse(LengthString, out IPLength))
                {
                    if (LengthIPList.Count == 0)
                    {
                        LengthIPList.Add(LengthString);
                    }
                    // So if list already contains one element, replace it with higher or lower
                    // if needed, depending on the list type(LowerLengthList or HigherLengthList) 
                    else
                    {
                        if (HigherBool)
                        {
                            if (IPLength > short.Parse(LengthIPList[0]))
                            {
                                LengthIPList[0] = LengthString;
                            }
                        }
                        else if (LowerBool)
                        {
                            if (IPLength < short.Parse(LengthIPList[0]))
                            {
                                LengthIPList[0] = LengthString;
                            }
                        }
                    }
                }
            }

            return LengthIPList;
        }
        
        /// <summary>
        /// Filters all received packets from PacketList
        /// </summary>
        private void FilterAllPackets()
        {
            // To filter all packets, we must refresh the whole list
            FilteredPacketList.Clear();

            lock (PacketList)
            {
                foreach (IPPacket packet in PacketList)
                {
                    lock (FilteredPacketList)
                    {
                        AddToFilteredList(packet);
                    }
                }
            }

            // This condition here avoids threading problem:
            //   If a new packet is captured just before FilterAllPackets() is called, 
            //   this removes all newPackets that arrived before this function call.
            while (FilteredPacketList.Count > 2)
            {
                uint firstPacketID = filteredPacketList[0].PacketID;
                uint lastPacketID = filteredPacketList[filteredPacketList.Count - 2].PacketID;

                if (firstPacketID > lastPacketID)
                {
                    filteredPacketList.RemoveAt(0);
                    continue;
                }
                break;
            }
        }

        /// <summary>
        /// Converts IP packet data from byte array to hexadecimal and char
        /// and stores them in HexPacketData CharPacketData properties
        /// </summary>
        private void GetPacketHexAndCharData()
        {
            int length = SelectedPacket.IPHeader[0].TotalLength;

            StringBuilder charStringBuilder = new StringBuilder();
            StringBuilder hexStringBuilder = new StringBuilder();

            // Copy header and message from selected IP packet to packetData
            byte[] packetData = new byte[length];
            Array.Copy(SelectedPacket.ByteIPHeader, packetData, SelectedPacket.ByteIPHeader.Length);
            Array.Copy(SelectedPacket.ByteIPMessage, 0, packetData, SelectedPacket.ByteIPHeader.Length, SelectedPacket.ByteIPMessage.Length);

            for (int i = 0; i < length; i++)
            {
                if (packetData[i] > 31 && packetData[i] < 128)
                    charStringBuilder.Append((char)packetData[i]);
                else
                    charStringBuilder.Append(".");
            }
            
            for (int i = 0; i < length; i++)
            {
                hexStringBuilder.Append(packetData[i].ToString("x2") + " ");
            }

            CharPacketData = charStringBuilder.ToString();
            HexPacketData = hexStringBuilder.ToString();
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

        public ICommand OpenHelp { get; private set; }

        private void OpenHelpExecute()
        {
            CurrentViewModel = helpViewModel;
        }

        public ICommand StartCapture { get; private set; }

        private void StartCaptureExecute()
        {
            if (string.IsNullOrEmpty(SelectedAddress))
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
                    StatsHandler.Timer.Start();
                    StatsHandler.CaptureStartTime = DateTime.Now;
                    IsInterfaceChangeAllowed = false;
                    IsStartEnabled = false;
                    IsStopEnabled = true;
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
                StatsHandler.Timer.Stop();
                IsInterfaceChangeAllowed = true;
                IsStartEnabled = true;
                IsStopEnabled = false;
            }
        }

        public ICommand ClearPacketList { get; private set; }

        private void ClearPacketListExecute()
        {
            PacketList.Clear();
            FilteredPacketList.Clear();
            filter = FilterBox;
            StatsHandler.Timer.Stop();

            if (monitor != null)
            {
                StatsHandler.CaptureStartTime = DateTime.Now;
                StatsHandler.Timer.Start();
            }

            SelectedPacketTree.Clear();
            HexPacketData = "";
            CharPacketData = "";
            IsClearEnabled = false;
        }

        public ICommand ResetFilter { get; private set; }

        private void ResetFilterExecute()
        {
            FilterBox = "";
            filter = "";
            FilterAllPackets();
            IsFilterEnabled = false;
            IsResetEnabled = false;
        }

        public ICommand ApplyFilter { get; private set; }

        private void ApplyFilterExecute()
        {
            filter = FilterBox;
            IsFilterEnabled = false;
            FilterAllPackets();
        }

        public ICommand RefreshDeviceAddressList { get; private set; }

        private void RefreshDeviceAddressListExecute()
        {
            string prevSelectedAddress = SelectedAddress;

            DeviceAddressList.Clear();
            GetAddresses();

            if (DeviceAddressList.Contains(prevSelectedAddress))
            {
                SelectedAddress = prevSelectedAddress;
            }
        }
        #endregion
    }
}