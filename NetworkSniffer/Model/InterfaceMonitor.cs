using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace NetworkSniffer.Model
{
    class InterfaceMonitor
    {
        private Socket socket;
        private IPAddress ipAddress;

        public InterfaceMonitor(string ip)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            ipAddress = IPAddress.Parse(ip);
        }

        public void StartCapture()
        {
            /* Bind the socket to selected IP address */
            socket.Bind(new IPEndPoint(ipAddress, 0));

            /* Socket options apply only to IP packets */
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            byte[] byteTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4];
            /* ReceiveAll implies that all incoming and outgoing packets on the interface are captured.
             * Second option should be TRUE */
            socket.IOControl(IOControlCode.ReceiveAll, byteTrue, byteOut);     
        }

        public void StopCapture()
        {
            socket.Close();
        }
    }
}
