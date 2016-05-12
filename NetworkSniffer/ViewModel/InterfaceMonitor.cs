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
        #region Members
        private const uint MTU = 1024 * 64;
        private byte[] byteBufferData;
        private Socket socket;
        private IPAddress ipAddress;
        #endregion

        #region Constructors
        public InterfaceMonitor(string ip)
        {
            byteBufferData = new byte[MTU];
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            ipAddress = IPAddress.Parse(ip);
        }
        #endregion

        #region Methods
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

            byteBufferData = new byte[MTU];
            socket.BeginReceive(byteBufferData, 0, byteBufferData.Length,
                                SocketFlags.None, new AsyncCallback(this.ReceiveData), null);
        }

        private void ReceiveData(IAsyncResult asyncResult)
        {
            try
            {
                int bytesReceived = socket.EndReceive(asyncResult);

                byte[] receivedData = new byte[bytesReceived];
                Array.Copy(byteBufferData, 0, receivedData, 0, bytesReceived);

                IPPacket newPacket = new IPPacket(receivedData, bytesReceived);
                if (newPacketEventHandler != null)
                {
                    newPacketEventHandler(newPacket);
                }
                
                socket.BeginReceive(byteBufferData, 0, byteBufferData.Length,
                                    SocketFlags.None, new AsyncCallback(this.ReceiveData), null);
            }
            catch (Exception e)
            {
                //test
                //System.Windows.MessageBox.Show(e.Message.ToString(), "Receive data error");
                StopCapture();
            }

        }

        public void StopCapture()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
                ipAddress = null;
            }
        }
        #endregion

        public event NewPacketEventHandler newPacketEventHandler;
        public delegate void NewPacketEventHandler(IPPacket newPacket);
    }
}
