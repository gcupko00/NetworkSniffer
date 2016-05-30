using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using NetworkSniffer.Model;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class contains properties that the main View can data bind to.
    /// </summary>
    public class MainViewModel : ViewModelBase
    {
        #region Fields
        private SnifferViewModel snifferViewModel = new SnifferViewModel();
        private AnalyzerViewModel analyzerViewModel = new AnalyzerViewModel();
        private HelpViewModel helpViewModel = new HelpViewModel();

        private InterfaceMonitor monitor;
        private string filter;
        private readonly object packetListLock = new object();

        // List of supported protocols
        private List<string> protocolList;
        // This second list is for exlcuding protocols using filter option, exmaple: "!udp"
        private List<string> protocolListToExclude;

        // List of IP addresses from src/dest syntax
        private List<string> srcIPList;
        private List<string> destIPList;

        // List of Ports from sp/dp syntax
        private List<string> srcPortList;
        private List<string> destPortList;

        // List of Lengths from length>/length< syntax
        private List<string> higherLengthList;
        private List<string> lowerLengthList;
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
            RefreshInterfaceList = new RelayCommand(() => RefreshInterfaceListExecute());

            // Initializing the list of valid filter conditions
            protocolList = new List<string>();
            protocolListToExclude = new List<string>();
            srcIPList = new List<string>();
            destIPList = new List<string>();
            srcPortList = new List<string>();
            destPortList = new List<string>();
            higherLengthList = new List<string>();
            lowerLengthList = new List<string>();

            InterfaceList = new ObservableCollection<IPNetworkInterface>();
            PacketList = new ObservableCollection<IPPacket>();
            FilteredPacketList = new ObservableCollection<IPPacket>();
            SelectedPacketTree = new ObservableCollection<IPPacket>();
            GetInterfaces();
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
        public ObservableCollection<IPNetworkInterface> InterfaceList { get; private set; }

        private IPNetworkInterface selectedInterface;
        /// <summary>
        /// Currently selected IP address of an interface on which packets are being captured
        /// </summary>
        public IPNetworkInterface SelectedInterface
        {
            get
            {
                return selectedInterface;
            }
            set
            {
                selectedInterface = value;
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
        /// Gets IP interfaces which are up
        /// </summary>
        private void GetInterfaces()
        {
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            InterfaceList.Add(new IPNetworkInterface
                            {
                                InterfaceAddress = ip.Address.ToString(),
                                InterfaceName = networkInterface.Name
                            });
                        }
                    }
                }
            }

            if (InterfaceList.Count > 0)
            {
                SelectedInterface = InterfaceList[0];
            }
            else
            {
                selectedInterface = null;
            }

            RaisePropertyChanged("SelectedInterface");
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
            if (string.IsNullOrEmpty(filter))
            {
                FilteredPacketList.Add(newPacket);
                return;
            }

            // If none of the substrings uses the proper syntax, ignore it and add packet
            // as if there was no filter at all.
            if (protocolList.Count == 0 && protocolListToExclude.Count == 0 && srcIPList.Count == 0 &&
                destIPList.Count == 0 && srcPortList.Count == 0 && destPortList.Count == 0 &&
                higherLengthList.Count == 0 && lowerLengthList.Count == 0)
            {
                FilteredPacketList.Add(newPacket);
                return;
            }

            // These are rules a newPacket must satisfy to be added in the FilteredPacketList.
            // By default all rules are true, so in case one of the condition list is empty
            // a newPacket could be added to FilteredList. Otherwise it is set to false once it
            // enters foreach loop where it must satisfy the conditon to be set to true
            bool IncludeProtocolRule = true;
            bool ExcludeProtocolRule = false;
            bool SrcIPRule = true;
            bool DstIPRule = true;
            bool SrcPortRule = true;
            bool DestPortRule = true;
            bool LowerLengthRule = true;
            bool HigherLengthRule = true;

            // Checking empty protocolList would change the default value of IncludeProtocolRule to false
            if (protocolList.Count != 0)
            {
                IncludeProtocolRule = ApplyProtocolRule(newPacket, protocolList);
            }

            if (protocolListToExclude.Count != 0)
            {
                ExcludeProtocolRule = ApplyProtocolRule(newPacket, protocolListToExclude);
            }

            foreach (string ip in srcIPList)
            {
                SrcIPRule = false;
                if (ip == newPacket.IPHeader[0].SourceIPAddress.ToString())
                {
                    SrcIPRule = true;
                    break;
                }
            }

            foreach (string ip in destIPList)
            {
                DstIPRule = false;
                if (ip == newPacket.IPHeader[0].DestinationIPAddress.ToString())
                {
                    DstIPRule = true;
                    break;
                }
            }

            foreach (string port in srcPortList)
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

            foreach (string port in destPortList)
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

            ushort packetLength = newPacket.IPHeader[0].TotalLength;
            foreach (string LowerLength in lowerLengthList)
            {
                LowerLengthRule = false;
                ushort lowerLenght = ushort.Parse(LowerLength);
                
                if (lowerLenght > packetLength)
                {
                    LowerLengthRule = true;
                    break;
                }
            }

            foreach (string HigherLength in higherLengthList)
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
            if (IncludeProtocolRule == true && ExcludeProtocolRule == false && SrcIPRule == true &&
                DstIPRule == true && SrcPortRule == true && DestPortRule == true &&
                LowerLengthRule == true && HigherLengthRule == true)
            {
                FilteredPacketList.Add(newPacket);
            }            
        }

        /// <summary>
        /// Returns bool which indicates wheter the packet satisfies given protocol rule
        /// </summary>
        /// <param name="newPacket"></param>
        /// <param name="ProtocolList"></param>
        private bool ApplyProtocolRule(IPPacket newPacket, List<string> ProtocolList)
        {
            foreach (string protocol in ProtocolList)
            {
                if (protocol.Equals("UDP") && newPacket.UDPPacket.Count > 0)
                {
                    return true;
                }
                else if (protocol.Equals("TCP") && newPacket.TCPPacket.Count > 0)
                {
                    return true;
                }
                else if (protocol.Equals("IGMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "IGMP")
                {
                    return true;
                }
                else if (protocol.Equals("ICMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "ICMP")
                {
                    return true;
                }
                else if (protocol.Equals("DNS") && 
                    newPacket.UDPPacket.Count > 0 &&
                    (newPacket.UDPPacket[0].UDPHeader[0].DestinationPort == 53 ||
                    newPacket.UDPPacket[0].UDPHeader[0].SourcePort == 53))
                {
                    return true;
                }
                else if (protocol.Equals("HTTPS") && 
                    ((newPacket.UDPPacket.Count > 0 &&
                     newPacket.UDPPacket[0].ApplicationProtocolType.PortName.Equals(protocol)) ||
                     (newPacket.TCPPacket.Count > 0 &&
                     newPacket.TCPPacket[0].ApplicationProtocolType.PortName.Equals(protocol))))
                {
                    return true;
                }
                else if (protocol.Equals("HTTP") && 
                    ((newPacket.UDPPacket.Count > 0 &&
                     newPacket.UDPPacket[0].ApplicationProtocolType.PortName.Equals(protocol)) ||
                     (newPacket.TCPPacket.Count > 0 &&
                     newPacket.TCPPacket[0].ApplicationProtocolType.PortName.Equals(protocol))))
                {
                    return true;
                }
                else if (protocol.Equals("SSH") && 
                    ((newPacket.UDPPacket.Count > 0 &&
                     newPacket.UDPPacket[0].ApplicationProtocolType.PortName.Equals(protocol)) ||
                     (newPacket.TCPPacket.Count > 0 &&
                     newPacket.TCPPacket[0].ApplicationProtocolType.PortName.Equals(protocol))))
                {
                    return true;
                }
                else if (protocol.Equals("IRC") && 
                    ((newPacket.UDPPacket.Count > 0 &&
                     newPacket.UDPPacket[0].ApplicationProtocolType.PortName.Equals(protocol)) ||
                     (newPacket.TCPPacket.Count > 0 &&
                     newPacket.TCPPacket[0].ApplicationProtocolType.PortName.Equals(protocol))))
                {
                    return true;
                }
            }

            return false;
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
                    // if needed, depending on the list type(lowerLengthList or higherLengthList) 
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

        /// <summary>
        /// Clears all filter lists - conditions
        /// </summary>
        private void ClearFilterLists()
        {
            protocolList.Clear();
            protocolListToExclude.Clear();
            srcIPList.Clear();
            destIPList.Clear();
            srcPortList.Clear();
            destPortList.Clear();
            higherLengthList.Clear();
            lowerLengthList.Clear();
        }

        /// <summary>
        /// Parse filter string into a list of valid filter conditions
        /// </summary>
        private void ParseFilterConditions()
        {
            // Set filter validity to default since there is no filter
            if (string.IsNullOrEmpty(filter))
            {
                FilterValidity = "Transparent";
                return;
            }

            // Split filter into substrings and make it all uppercase
            List<string> filterList = new List<string>(filter.ToUpper().Split(' '));

            // A list of allowed supported protocols
            string[] allowedProtocols = { "UDP", "TCP", "IGMP", "ICMP", "DNS",
                                          "HTTPS", "HTTP", "SSH", "IRC" };

            // Remove all substrings that are not in list of allowed filters
            // But if a substring is src/dest ip or sp/dp port, tranfser it to its List
            for (int i = filterList.Count - 1; i >= 0; i--)
            {
                // Next two If conditions will add IP addresses to IP Lists, if there are any
                if (filterList[i].Contains("SRC="))
                {
                    srcIPList = ValidIPAddress(srcIPList, filterList[i]);
                }
                else if (filterList[i].Contains("DEST="))
                {
                    destIPList = ValidIPAddress(destIPList, filterList[i]);
                }

                // Next two If conditions will add Ports to Port Lists, if there are any
                else if (filterList[i].Contains("SP="))
                {
                    srcPortList = ValidPort(srcPortList, filterList[i]);
                }
                else if (filterList[i].Contains("DP="))
                {
                    destPortList = ValidPort(destPortList, filterList[i]);
                }

                // Next two If conditions will add Length to Length Lists, if there are any
                else if (filterList[i].Contains("LENGTH>"))
                {
                    higherLengthList = ValidIPLength(higherLengthList, filterList[i]);
                }
                else if (filterList[i].Contains("LENGTH<"))
                {
                    lowerLengthList = ValidIPLength(lowerLengthList, filterList[i]);
                }

                // Fill the protocol list with strings from AllowedProtocol string array
                else
                {
                    foreach (string protocol in allowedProtocols)
                    {
                        // Fills protocolList
                        if (string.Equals(protocol, filterList[i]))
                        {
                            if (protocolList.Contains(filterList[i]) == false)
                            {
                                protocolList.Add(protocol);
                            }
                        }
                        // Fills the opposite list - protocolListToExclude
                        if (string.Equals("!" + protocol, filterList[i]))
                        {
                            if (protocolListToExclude.Contains(filterList[i]) == false)
                            {
                                protocolListToExclude.Add(protocol);
                            }
                        }
                    }
                }
            }
            // Filter is not valid so paint it red.
            if (protocolList.Count == 0 && protocolListToExclude.Count == 0 && srcIPList.Count == 0 &&
                destIPList.Count == 0 && srcPortList.Count == 0 && destPortList.Count == 0 &&
                higherLengthList.Count == 0 && lowerLengthList.Count == 0)
            {
                FilterValidity = "LightSalmon";
                return;
            }
            // Else filter is valid and paint it green.
            FilterValidity = "LightGreen";
        }

        /// <summary>
        /// Empties selected packet tree and packet data properties
        /// </summary>
        private void ClearSelectedPacketData()
        {
            SelectedPacketTree.Clear();
            HexPacketData = "";
            CharPacketData = "";
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
            if (SelectedInterface == null)
            {
                MessageBox.Show("Please select device address");
            }
            else if (!UserIdentityHandler.IsUserAdministrator())
            {
                MessageBox.Show("Please start program with administrator privileges");
            }
            else
            {
                try
                {
                    if (monitor == null)
                    {
                        monitor = new InterfaceMonitor(SelectedInterface.InterfaceAddress);
                        monitor.newPacketEventHandler += new InterfaceMonitor.NewPacketEventHandler(ReceiveNewPacket);
                        monitor.StartCapture();
                        StatsHandler.Timer.Start();
                        StatsHandler.StopWatch.Start();
                        IsInterfaceChangeAllowed = false;
                        IsStartEnabled = false;
                        IsStopEnabled = true;
                    }
                }
                catch (Exception e)
                {
                    MessageBox.Show(e.Message, "Could not start capture!");
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
                StatsHandler.StopWatch.Stop();
                IsInterfaceChangeAllowed = true;
                IsStartEnabled = true;
                IsStopEnabled = false;
            }
            if (FilteredPacketList.Count == 0)
            {
                StatsHandler.StopWatch.Reset();
            }
        }

        public ICommand ClearPacketList { get; private set; }

        private void ClearPacketListExecute()
        {
            PacketList.Clear();
            FilteredPacketList.Clear();
            StatsHandler.ResetStats();

            if (monitor != null)
            {
                StatsHandler.StopWatch.Start();
            }

            ClearSelectedPacketData();
            IsClearEnabled = false;
        }

        public ICommand ResetFilter { get; private set; }

        private void ResetFilterExecute()
        {
            FilterBox = "";
            ApplyFilterExecute();
            ClearSelectedPacketData();
            IsFilterEnabled = false;
            IsResetEnabled = false;
        }

        public ICommand ApplyFilter { get; private set; }

        private void ApplyFilterExecute()
        {
            ClearFilterLists();
            filter = FilterBox;
            ParseFilterConditions();
            FilterAllPackets();
            ClearSelectedPacketData();
            IsFilterEnabled = false;

            if(string.IsNullOrEmpty(filter))
            {
                IsResetEnabled = false;
            }
        }

        public ICommand RefreshInterfaceList { get; private set; }

        private void RefreshInterfaceListExecute()
        {
            IPNetworkInterface prevSelectedAddress = SelectedInterface;

            InterfaceList.Clear();
            GetInterfaces();

            if (InterfaceList.Contains(prevSelectedAddress))
            {
                SelectedInterface = prevSelectedAddress;
            }
            else if (InterfaceList.Count > 0)
            {
                SelectedInterface = InterfaceList[0];
            }
            else
            {
                SelectedInterface = null;
            }

            RaisePropertyChanged("SelectedInterface");
        }
        #endregion
    }
}