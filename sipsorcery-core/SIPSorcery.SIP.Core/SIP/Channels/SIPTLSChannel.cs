//-----------------------------------------------------------------------------
// Filename: SIPTLSChannel.cs
//
// Description: SIP transport for TLS over TCP.
// 
// History:
// 13 Mar 2009	Aaron Clauson	Created.
//
// License: 
// This software is licensed under the BSD License http://www.opensource.org/licenses/bsd-license.php
//
// Copyright (c) 2006 Aaron Clauson (aaron@sipsorcery.com), SIP Sorcery PTY LTD, Hobart, Australia (www.sipsorcery.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that 
// the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. 
// Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following 
// disclaimer in the documentation and/or other materials provided with the distribution. Neither the name of SIP Sorcery PTY LTD. 
// nor the names of its contributors may be used to endorse or promote products derived from this software without specific 
// prior written permission. 
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
// BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
// IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//-----------------------------------------------------------------------------

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Cache;
using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using SIPSorcery.Sys;
using log4net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SIPSorcery.SIP
{
    public delegate bool SIPTLSChannelInboundCertificateValidationCallback(SIPTLSChannel channel, IPEndPoint remoteEndpoint, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors);
    public delegate bool SIPTLSChannelOutboundCertificateValidationCallback(SIPTLSChannel channel, IPEndPoint remoteEndpoint, string serverFQDN, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors);

    public delegate void SIPTLSChannelConnectionOpened(SIPTLSChannel channel, SIPConnection connection);
    public delegate void SIPTLSChannelConnectionClosed(SIPTLSChannel channel, SIPConnection connection);


    public class SIPTLSChannel : SIPChannel
    {
        private const string ACCEPT_THREAD_NAME = "siptls-";
        private const string PRUNE_THREAD_NAME = "siptlsprune-";
        private const int LINGER_TIMEOUT = 5; //Sekunden

        /// <summary>
        /// Maximum number of connections for the TLS listener.
        /// </summary>
        private const int MAX_TLS_CONNECTIONS = 1000;              
        //private const int MAX_TLS_CONNECTIONS_PER_IPADDRESS = 10;   // Maximum number of connections allowed for a single remote IP address.
        private static int MaxSIPTCPMessageSize = SIPConstants.SIP_MAXIMUM_RECEIVE_LENGTH;

        private TcpListener m_tlsServerListener;
        //private bool m_closed = false;
        private Thread m_tlsServerListenerThread;

        private readonly Dictionary<string, SIPConnection> m_connectedSockets = new Dictionary<string, SIPConnection>();
        /// <summary>
        /// List of connecting sockets to avoid SIP re-transmits initiating multiple connect attempts.
        /// </summary>
        private readonly List<string> m_connectingSockets = new List<string>();

        private readonly object m_connectAndSendSync;
        private readonly Dictionary<string, Queue<ITlsChannelJob>> m_endpointJobLists;

        private interface ITlsChannelJob
        {
            void Execute();
            void Abort();
        }

        private class JobSend : ITlsChannelJob
        {
            private Action<IPEndPoint, byte[], string, Action<bool>, Func<bool>> m_sendAction;
            private IPEndPoint m_endPoint;
            private byte[] m_buffer;
            private string m_fqdn;
            private Action<bool> m_onSendDone;
            private Func<bool> m_isCanceled;

            public JobSend(Action<IPEndPoint, byte[], string, Action<bool>, Func<bool>> a_sendAction, IPEndPoint a_endpoint, byte[] a_buffer, string a_fqdn, Action<bool> a_onSendDone, Func<bool> a_isCanceled)
            {
                m_sendAction = a_sendAction;
                m_endPoint = a_endpoint;
                m_buffer = a_buffer;
                m_fqdn = a_fqdn;
                m_onSendDone = a_onSendDone;
                m_isCanceled = a_isCanceled;
            }

            public void Execute()
            {
                m_sendAction.Invoke(m_endPoint, m_buffer, m_fqdn, m_onSendDone, m_isCanceled);
            }

            public void Abort()
            {
                m_onSendDone?.Invoke(false);
            }
        }

        private class JobAccept : ITlsChannelJob
        {
            private string m_endpointKey;
            private IPEndPoint m_remotEndPoint;
            private TcpClient m_tcpClient;
            private Action<string, IPEndPoint, TcpClient> m_acceptAction;

            public JobAccept(Action<string, IPEndPoint, TcpClient> a_acceptAction, string a_endpointKey, IPEndPoint a_remoteEndPoint, TcpClient a_tcpClient)
            {
                m_endpointKey = a_endpointKey;
                m_remotEndPoint = a_remoteEndPoint;
                m_tcpClient = a_tcpClient;
                m_acceptAction = a_acceptAction;
            }

            public void Execute()
            {
                m_acceptAction.Invoke(m_endpointKey, m_remotEndPoint, m_tcpClient);
            }

            public void Abort()
            {
                try
                {
                    m_tcpClient.Close();
                }
                catch
                {
                }
            }
        }

        //private string m_certificatePath;
        private readonly X509Certificate2 m_serverCertificate;
        private readonly string m_fqdn;
        private readonly SslProtocols m_sslProtocols;
        private readonly bool m_clientCertificateRequired;
        private readonly bool m_checkCertificateRevocation;
        private readonly bool m_useAnyAvailablePortForSend;

        private SIPTLSChannelInboundCertificateValidationCallback m_inboundCertificateValidationCallback;
        private SIPTLSChannelOutboundCertificateValidationCallback m_outboundCertificateValidationCallback;
        
        private new ILog logger = AppState.GetLogger("siptls-channel");

        public event SIPTLSChannelConnectionOpened ConnectionOpened;
        public event SIPTLSChannelConnectionClosed ConnectionClosed;

        private readonly Action<string> m_logDebug;
        private readonly Action<string> m_logError;

        private long m_invokeAsyncOperationIdCounter;


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
        private const uint HANDLE_FLAG_INHERIT = 1;


        public SIPTLSChannel(X509Certificate2 serverCertificate, string fqdn, SslProtocols sslProtocols, bool clientCertificateRequired, bool checkCertificateRevocation,
            SIPTLSChannelInboundCertificateValidationCallback inboundCertificateValidationCallback,
            SIPTLSChannelOutboundCertificateValidationCallback outboundCertificateValidationCallback,
            IPEndPoint endPoint, bool useAnyAvailablePortForSend, Action<string> logDebug, Action<string> logError)
        {
            if (serverCertificate == null)
            {
                throw new ArgumentNullException(nameof(serverCertificate), "An X509 certificate must be supplied for a SIP TLS channel.");
            }

            if (endPoint == null)
            {
                throw new ArgumentNullException(nameof(endPoint), "An IP end point must be supplied for a SIP TLS channel.");
            }

            m_fqdn = fqdn ?? serverCertificate.GetNameInfo(X509NameType.SimpleName, false);
            m_isReliable = true;
            m_isTLS = true;
            m_serverCertificate = serverCertificate;
            m_sslProtocols = sslProtocols;
            m_clientCertificateRequired = clientCertificateRequired;
            m_checkCertificateRevocation = checkCertificateRevocation;
            m_useAnyAvailablePortForSend = useAnyAvailablePortForSend;
            m_inboundCertificateValidationCallback = inboundCertificateValidationCallback;
            m_outboundCertificateValidationCallback = outboundCertificateValidationCallback;

            m_connectAndSendSync = new object();
            m_endpointJobLists = new Dictionary<string, Queue<ITlsChannelJob>>();

            m_logDebug = logDebug;
            m_logError = logError;

            m_invokeAsyncOperationIdCounter = 0;

            Initialise(endPoint);
        }

        public SIPTLSChannel(X509Certificate2 serverCertificate, IPEndPoint endPoint) : 
            this(serverCertificate, null, SslProtocols.Default, false, false, null, null, endPoint, false, null, null)
        {
        }

        private void Initialise(IPEndPoint localEndPoint)
        {
            try
            {
                if (m_inboundCertificateValidationCallback == null)
                    m_inboundCertificateValidationCallback = InboundCertificateValidation;
                if (m_outboundCertificateValidationCallback == null)
                    m_outboundCertificateValidationCallback = OutboundCertificateValidation;

                m_tlsServerListener = new TcpListener(localEndPoint);
                m_tlsServerListener.Server.LingerState = new LingerOption(true, LINGER_TIMEOUT);
                SetHandleInformation(m_tlsServerListener.Server.Handle, HANDLE_FLAG_INHERIT, 0);

                m_tlsServerListener.Start(MAX_TLS_CONNECTIONS);
                m_localSIPEndPoint = new SIPEndPoint(SIPProtocolsEnum.tls, (IPEndPoint)m_tlsServerListener.Server.LocalEndPoint, m_fqdn);

                LocalTCPSockets.Add(((IPEndPoint)m_tlsServerListener.Server.LocalEndPoint).ToString());

                m_tlsServerListenerThread = new Thread( ()=> AcceptConnections(ACCEPT_THREAD_NAME + m_localSIPEndPoint.Port) );
                m_tlsServerListenerThread.IsBackground = true;
                m_tlsServerListenerThread.Start();

                ThreadPool.QueueUserWorkItem(delegate { PruneConnections(PRUNE_THREAD_NAME + m_localSIPEndPoint.Port); });

                logger.Debug("SIP TLS Channel listener created " + m_localSIPEndPoint.GetIPEndPoint() + ".");
            }
            catch (Exception excp)
            {
                m_logError?.Invoke($"Exception SIPTLSChannel Initialise. {excp}");
                logger.Error("Exception SIPTLSChannel Initialise. " + excp);
                throw;
            }
        }

        private void AcceptConnections(string threadName)
        {
            try
            {
                Thread.CurrentThread.Name = threadName;

                logger.Debug("SIPTLSChannel socket on " + m_localSIPEndPoint + " accept connections thread started.");

                while (!Closed)
                {
                    IPEndPoint remoteEndPoint = null;
                    try
                    {
                        // Blocking call - Waiting for connection ...
                        var tcpClient = m_tlsServerListener.AcceptTcpClient();
                        if (Closed)
                        {
                            tcpClient.Close();
                            break;
                        }

                        // Connected
                        SetHandleInformation(tcpClient.Client.Handle, HANDLE_FLAG_INHERIT, 0);
                        remoteEndPoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
                        var endpointKey = remoteEndPoint.ToString();
                        var job = new JobAccept((key, endpoint, client) => StartAuthenticateAsServer(key, endpoint, client), endpointKey, remoteEndPoint, tcpClient);
                        ExecuteJobOrQueueIt(endpointKey, job);
                    }
                    catch (Exception e)
                    {
                        logger.Error("SIPTLSChannel Accept Connection Exception. " + e);
                        m_logError?.Invoke($"SIPTLSChannel Accept Connection Exception: {e}");
                        if (null != remoteEndPoint)
                        {
                            FinishJobAndStartNextOne(remoteEndPoint);
                        }
                    }
                }

                logger.Debug("SIPTLSChannel socket on " + m_localSIPEndPoint + " listening halted.");
            }
            catch (Exception excp)
            {
                logger.Error("Exception SIPTLSChannel Listen. " + excp);
                m_logError?.Invoke($"Exception SIPTLSChannel Listen: {excp}");
            }
        }

        private void StartAuthenticateAsServer(string a_endpointKey, IPEndPoint a_remoteEndPoint, TcpClient a_tcpClient)
        {
            try
            {
                bool startAuthentication = true;
                lock (m_connectedSockets)
                {
                    if (m_connectingSockets.Contains(a_endpointKey) || m_connectedSockets.ContainsKey(a_endpointKey))
                    {
                        logger.Debug($"SIP TLS Channel refused from {a_endpointKey} because of existing or pending connection.");
                        startAuthentication = false;
                    }
                    else
                    {
                        m_connectingSockets.Add(a_endpointKey);
                    }
                }

                if (startAuthentication)
                {
                    try
                    {
                        logger.Debug("SIP TLS Channel connection accepted from " + a_remoteEndPoint + ".");

                        var sslStream = new SslStream(a_tcpClient.GetStream(), false, (sender, certificate, chain, errors) => m_inboundCertificateValidationCallback(this, a_remoteEndPoint, certificate, chain, errors));
                        var sipTlsConnection = new SIPConnection(this, a_tcpClient, sslStream, a_remoteEndPoint, SIPProtocolsEnum.tls, SIPConnectionsEnum.Listener, m_logDebug, m_logError);
                        sslStream.BeginAuthenticateAsServer(m_serverCertificate, m_clientCertificateRequired, m_sslProtocols, m_checkCertificateRevocation, EndAuthenticateAsServer, sipTlsConnection);
                    }
                    catch
                    {
                        lock (m_connectedSockets)
                        {
                            m_connectingSockets.Remove(a_remoteEndPoint.ToString());
                        }

                        throw;
                    }
                }
                else
                {
                    a_tcpClient.Close();
                    FinishJobAndStartNextOne(a_remoteEndPoint);
                }
            }
            catch (Exception excp)
            {
                logger.Error("Exception SIPTLSChannel StartAuthenticateAsServer. " + excp);
                m_logError?.Invoke($"Exception SIPTLSChannel StartAuthenticateAsServer: {excp}");
                FinishJobAndStartNextOne(a_remoteEndPoint);
            }
        }

        public void EndAuthenticateAsServer(IAsyncResult ar)
        {
            SIPConnection sipTlsConnection = (SIPConnection)ar.AsyncState;
            try
            {
                var sslStream = (SslStream) sipTlsConnection.SIPStream;
                sslStream.EndAuthenticateAsServer(ar);

                const int fiveSeconds = 5000;
                sslStream.ReadTimeout = fiveSeconds;
                sslStream.WriteTimeout = fiveSeconds;

                lock (m_connectedSockets)
                {
                    m_connectingSockets.Remove(sipTlsConnection.RemoteEndPoint.ToString());
                    m_connectedSockets.Add(sipTlsConnection.RemoteEndPoint.ToString(), sipTlsConnection);
                }
            }
            catch (Exception excp)
            {
                lock (m_connectedSockets)
                {
                    m_connectingSockets.Remove(sipTlsConnection.RemoteEndPoint.ToString());
                }

                logger.Error("Exception SIPTLSChannel EndAuthenticateAsServer. " + excp);
                m_logError?.Invoke($"Exception SIPTLSChannel EndAuthenticateAsServer: {excp}");

                return;
            }
            finally
            {
                FinishJobAndStartNextOne(sipTlsConnection.RemoteEndPoint);
            }

            FireConnectionOpened(sipTlsConnection);

            try
            {
                sipTlsConnection.SIPSocketDisconnected += SIPTLSSocketDisconnected;
                sipTlsConnection.SIPMessageReceived += SIPTLSMessageReceived;
                sipTlsConnection.SIPStream.BeginRead(sipTlsConnection.SocketBuffer, 0, MaxSIPTCPMessageSize, ReceiveCallback, sipTlsConnection);
            }
            catch (Exception excp)
            {
                logger.Error("Exception SIPTLSChannel EndAuthenticateAsServer. SIPStream.BeginRead: " + excp);
                m_logError?.Invoke($"Exception SIPTLSChannel EndAuthenticateAsServer. SIPStream.BeginRead: {excp}");
            }
        }

        public void ReceiveCallback(IAsyncResult ar)
        {
            var sipTlsConnection = (SIPConnection)ar.AsyncState;

            if (sipTlsConnection?.SIPStream != null && sipTlsConnection.SIPStream.CanRead)
            {
                try
                {
                    int bytesRead = sipTlsConnection.SIPStream.EndRead(ar);

                    if (sipTlsConnection.SocketReadCompleted(bytesRead))
                    {
                        sipTlsConnection.SIPStream.BeginRead(sipTlsConnection.SocketBuffer, sipTlsConnection.SocketBufferEndPosition, MaxSIPTCPMessageSize - sipTlsConnection.SocketBufferEndPosition, ReceiveCallback, sipTlsConnection);
                    }
                }
                catch (SocketException sockExcp)  // Occurs if the remote end gets disconnected.
                {
                    logger.Warn("SocketException SIPTLSChannel ReceiveCallback. " + sockExcp);
                    m_logError?.Invoke($"SocketException SIPTLSChannel ReceiveCallback: {sockExcp}");
                }
                catch (Exception excp)
                {
                    logger.Warn("Exception SIPTLSChannel ReceiveCallback. " + excp);
                    m_logError?.Invoke($"Exception SIPTLSChannel ReceiveCallback: {excp}");
                    SIPTLSSocketDisconnected(sipTlsConnection.RemoteEndPoint);
                }
            }
        }

        public override void Send(IPEndPoint destinationEndPoint, string message)
        {
            Send(destinationEndPoint, message, null, null);
        }

        public override void Send(IPEndPoint destinationEndPoint, string message, Action<bool> onSendDone, Func<bool> isCanceled)
        {
            byte[] messageBuffer = Encoding.UTF8.GetBytes(message);
            Send(destinationEndPoint, messageBuffer, onSendDone, isCanceled);
        }

        public override void Send(IPEndPoint dstEndPoint, byte[] buffer)
        {
            Send(dstEndPoint, buffer, null, null);
        }

        public override void Send(IPEndPoint dstEndPoint, byte[] buffer, Action<bool> onSendDone, Func<bool> isCanceled)
        {
            Send(dstEndPoint, buffer, (string)null, onSendDone, isCanceled);
        }

        public override void Send(IPEndPoint dstEndPoint, byte[] buffer, string serverCertificateName)
        {
            Send(dstEndPoint, buffer, serverCertificateName, null, null);
        }

        public override void Send(IPEndPoint dstEndPoint, byte[] buffer, string serverCertificateName, Action<bool> onSendDone, Func<bool> isCanceled)
        {
            try
            {
                if (buffer == null)
                {
                    onSendDone?.Invoke(false);
                    throw new ApplicationException("An empty buffer was specified to Send in SIPTLSChannel.");
                }

                var endpointKey = dstEndPoint.ToString();

                if (LocalTCPSockets.Contains(endpointKey))
                {
                    logger.Error($"SIPTLSChannel blocked Send to {endpointKey} as it was identified as a locally hosted TCP socket.\r\n{Encoding.UTF8.GetString(buffer)}");
                    m_logError?.Invoke($"SIPTLSChannel blocked Send to {{endpointKey}} as it was identified as a locally hosted TCP socket.\\r\\n{{Encoding.UTF8.GetString(buffer)}}");
                    onSendDone?.Invoke(false);
                    throw new ApplicationException("A Send call was made in SIPTLSChannel to send to another local TCP socket.");
                }

                if (serverCertificateName.IsNullOrBlank())
                {
                    lock (m_connectedSockets)
                    {
                        if (!m_connectedSockets.ContainsKey(endpointKey))
                        {
                            m_logError?.Invoke("The SIP TLS Channel must be provided with the name of the expected server certificate, please use alternative method.");
                            onSendDone?.Invoke(false);
                            throw new ApplicationException("The SIP TLS Channel must be provided with the name of the expected server certificate, please use alternative method.");
                        }
                    }
                }

                var job = new JobSend((endpPoint, buf, cert, done, canceled) => DoSend(endpPoint, buf, cert, done, canceled), dstEndPoint, buffer, serverCertificateName, onSendDone, isCanceled);
                ExecuteJobOrQueueIt(dstEndPoint.ToString(), job);
            }
            catch (Exception excp)
            {
                logger.Error("Exception (" + excp.GetType() + ") SIPTLSChannel Send (sendto=>" + dstEndPoint + "). " + excp);
                m_logError?.Invoke($"SIPTLSChannel.Send-Exception-Endpoint:'{dstEndPoint}'-Exception:{excp}");
                onSendDone?.Invoke(false);
                throw;
            }
        }

        private void DoSend(IPEndPoint dstEndPoint, byte[] buffer, string serverCertificateName, Action<bool> onSendDone, Func<bool> isCanceled)
        {
            try
            {
                if (isCanceled != null && isCanceled.Invoke())
                {
                    onSendDone?.Invoke(false);
                    logger.Warn("A SIPTLSChannel write operation to " + dstEndPoint + " was dropped as the underlaying transaction has timedout.");
                    m_logError?.Invoke("A SIPTLSChannel write operation to " + dstEndPoint + " was dropped as the underlaying transaction has timedout.");
                    FinishJobAndStartNextOne(dstEndPoint);
                    return;
                }

                SIPConnection sipTLSClient = null;
                var endpointKey = dstEndPoint.ToString();

                lock (m_connectedSockets)
                {
                    m_connectedSockets.TryGetValue(endpointKey, out sipTLSClient);
                }

                //
                // Verbindung ist bereits aufgebaut => Telegramm senden.
                //
                if (null != sipTLSClient) 
                {
                    try
                    {
                        if (sipTLSClient.SIPStream != null && sipTLSClient.SIPStream.CanWrite)
                        {
                            Interlocked.CompareExchange(ref m_invokeAsyncOperationIdCounter, 0, long.MaxValue);

                            var id = Interlocked.Increment(ref m_invokeAsyncOperationIdCounter);

                            sipTLSClient.OperationId = id;
                            sipTLSClient.SIPStream.BeginWrite(buffer, 0, buffer.Length, EndSend, new object[]{sipTLSClient, onSendDone});
                            sipTLSClient.LastTransmission = DateTime.Now;
                            return;
                        }

                        onSendDone?.Invoke(false);

                        logger.Warn("A SIPTLSChannel write operation to " + dstEndPoint + " was dropped as the stream was null or could not be written to.");
                        m_logError?.Invoke("A SIPTLSChannel write operation to " + dstEndPoint + " was dropped as the stream was null or could not be written to.");
                        FinishJobAndStartNextOne(dstEndPoint);
                        return;
                    }
                    catch (SocketException)
                    {
                        logger.Warn("Could not send to TLS socket " + dstEndPoint + ", closing and removing.");
                        m_logError?.Invoke($"Could not send to TLS socket '{dstEndPoint}', closing and removing.");

                        lock (m_connectedSockets)
                        {
                            m_connectedSockets.Remove(endpointKey);
                        }

                        sipTLSClient.SIPStream?.Close();
                    }
                }

                if (serverCertificateName.IsNullOrBlank())
                {
                    onSendDone?.Invoke(false);

                    m_logError?.Invoke("The SIP TLS Channel must be provided with the name of the expected server certificate, please use alternative method.");
                    FinishJobAndStartNextOne(dstEndPoint);
                    return;
                }

                bool tryConnect = false;
                lock (m_connectedSockets)
                {
                    if (!m_connectingSockets.Contains(endpointKey))
                    {
                        tryConnect = true;
                        m_connectingSockets.Add(endpointKey);
                    }
                }

                if (tryConnect)
                {
                    logger.Debug("Attempting to establish TLS connection to " + dstEndPoint + ".");
                    try
                    {
                        TcpClient tcpClient = new TcpClient();
                        tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, false);

                        tcpClient.Client.Bind(CreateEndpoint());
                        tcpClient.BeginConnect(dstEndPoint.Address, dstEndPoint.Port, EndConnect, new object[] {tcpClient, dstEndPoint, buffer, serverCertificateName, onSendDone });
                    }
                    catch (Exception e)
                    {
                        onSendDone?.Invoke(false);

                        lock (m_connectedSockets)
                        {
                            m_connectingSockets.Remove(endpointKey);
                        }

                        logger.Error("Exception (" + e.GetType() + ") SIPTLSChannel Send (sendto=>" + dstEndPoint + "); TcpClient.Bind or TcpClient.BeginConnect. " + e);
                        m_logError?.Invoke($"SIPTLSChannel.Send-Exception during invoking tcpClient.BeginConnect-Endpoint:'{endpointKey}'-Exception:{e}");

                        FinishJobAndStartNextOne(dstEndPoint);
                    }
                }
                else
                {
                    onSendDone?.Invoke(false);

                    logger.Warn("Could not send SIP packet to TLS " + dstEndPoint + " and another connection was already in progress so dropping message.");
                    m_logError?.Invoke($"Could not send SIP packet to TLS {dstEndPoint} and another connection was already in progress so dropping message.");
                    FinishJobAndStartNextOne(dstEndPoint);
                }
            }
            catch (Exception excp)
            {
                onSendDone?.Invoke(false);

                logger.Error("Exception (" + excp.GetType() + ") SIPTLSChannel DoSend (sendto=>" + dstEndPoint + "). " + excp);
                m_logError?.Invoke($"SIPTLSChannel.Send-Exception-Endpoint:'{dstEndPoint}'-Exception:{excp}");
                FinishJobAndStartNextOne(dstEndPoint);
            }
        }


        private IPEndPoint CreateEndpoint()
        {
            if (m_useAnyAvailablePortForSend)
            {
                const int useAnyAvailablePort = 0;
                return new IPEndPoint(m_localSIPEndPoint.Address, useAnyAvailablePort);
            }

            return m_localSIPEndPoint.GetIPEndPoint();
        }

        private void EndSend(IAsyncResult ar)
        {
            object[] stateObj = (object[])ar.AsyncState;
            SIPConnection sipConnection = (SIPConnection)stateObj[0];
            Action<bool> onSendDone = (Action<bool>)stateObj[1];
            IPEndPoint dstEndpoint = null;
            long? operationId = -1;
            try
            {
                operationId = sipConnection.OperationId;
                dstEndpoint = sipConnection.RemoteEndPoint;
                sipConnection.SIPStream.EndWrite(ar);
                onSendDone?.Invoke(true);

                OnSendComplete(EventArgs.Empty);
            }
            catch (Exception excp)
            {
                onSendDone?.Invoke(false);

                logger.Error("Exception EndSend. " + excp);
                m_logError(operationId.HasValue
                    ? $"SIPTLSChannel.EndSend Exception with OperationId '{operationId.Value}'. Exception: {excp}"
                    : $"SIPTLSChannel.EndSend Exception with missing OperationId . Exception: {excp}");
            }
            finally
            {
                FinishJobAndStartNextOne(dstEndpoint);
            }
        }

        protected override void OnSendComplete(EventArgs args)
        {
            base.OnSendComplete(args);
        }

        private void EndConnect(IAsyncResult ar)
        {
            object[] stateObj = (object[])ar.AsyncState;
            TcpClient tcpClient = (TcpClient)stateObj[0];
            IPEndPoint dstEndPoint = (IPEndPoint)stateObj[1];
            byte[] buffer = (byte[])stateObj[2];
            string serverCN = (string)stateObj[3];
            Action<bool> onSendDone = (Action<bool>) stateObj[4];

            try
            {
                tcpClient.EndConnect(ar);

                SslStream sslStream = new SslStream(tcpClient.GetStream(), false, (sender, certificate, chain, errors) => m_outboundCertificateValidationCallback(this, dstEndPoint, serverCN, certificate, chain, errors), null);
                //DisplayCertificateInformation(sslStream);

                SIPConnection callerConnection = new SIPConnection(this, tcpClient, sslStream, dstEndPoint, SIPProtocolsEnum.tls, SIPConnectionsEnum.Caller, m_logDebug, m_logError);

                sslStream.BeginAuthenticateAsClient(serverCN, new X509Certificate2Collection() { m_serverCertificate }, m_sslProtocols, m_checkCertificateRevocation, EndAuthenticateAsClient, new object[] { tcpClient, dstEndPoint, buffer, callerConnection, onSendDone });
            }
            catch (Exception excp)
            {
                onSendDone?.Invoke(false);
                logger.Error("Exception SIPTLSChannel EndConnect. " + excp);
                m_logError?.Invoke("Exception SIPTLSChannel EndConnect. " + excp);

                lock (m_connectedSockets)
                {
                    m_connectingSockets.Remove(dstEndPoint.ToString());
                }

                if (tcpClient != null)
                {
                    try
                    {
                        tcpClient.Close();
                    }
                    catch(Exception closeExcp)
                    {
                        logger.Warn("Exception SIPTLSChannel EndConnect Close TCP Client. " + closeExcp);
                        m_logError?.Invoke("Exception SIPTLSChannel EndConnect Close TCP Client. " + closeExcp);
                    }
                }

                FinishJobAndStartNextOne(dstEndPoint);
            }
        }

        private void EndAuthenticateAsClient( IAsyncResult ar )
        {
            object[] stateObj = (object[]) ar.AsyncState;
            TcpClient tcpClient = (TcpClient) stateObj[0];
            IPEndPoint dstEndPoint = (IPEndPoint) stateObj[1];
            byte[] buffer = (byte[]) stateObj[2];
            SIPConnection callerConnection = (SIPConnection) stateObj[3];
            Action<bool> onSendDone = (Action<bool>) stateObj[4];
            try
            {
                SslStream sslStream = (SslStream) callerConnection.SIPStream;

                sslStream.EndAuthenticateAsClient(ar);

                if (tcpClient != null && tcpClient.Connected)
                {
                    //SIPConnection callerConnection = new SIPConnection(this, sslStream, dstEndPoint, SIPProtocolsEnum.tls, SIPConnectionsEnum.Caller);
                    lock (m_connectedSockets)
                    {
                        m_connectingSockets.Remove(dstEndPoint.ToString());
                        m_connectedSockets.Add(callerConnection.RemoteEndPoint.ToString(), callerConnection);
                    }
                }
                else
                {
                    onSendDone?.Invoke(false);

                    logger.Warn("Could not establish TLS connection to " + callerConnection.RemoteEndPoint + ".");
                    m_logError?.Invoke("Could not establish TLS connection to " + callerConnection.RemoteEndPoint + ".");

                    lock (m_connectedSockets)
                    {
                        m_connectingSockets.Remove(dstEndPoint.ToString());
                    }

                    FinishJobAndStartNextOne(dstEndPoint);
                    return;
                }
            }
            catch (Exception excp)
            {
                onSendDone?.Invoke(false);

                logger.Error("Exception SIPTLSChannel EndAuthenticateAsClient. " + excp);
                m_logError?.Invoke("Exception SIPTLSChannel EndAuthenticateAsClient. " + excp);

                lock (m_connectedSockets)
                {
                    m_connectingSockets.Remove(dstEndPoint.ToString());
                }

                FinishJobAndStartNextOne(dstEndPoint);
                return;
            }

            FireConnectionOpened(callerConnection);

            try
            {
                callerConnection.SIPSocketDisconnected += SIPTLSSocketDisconnected;
                callerConnection.SIPMessageReceived += SIPTLSMessageReceived;
                //byte[] receiveBuffer = new byte[MaxSIPTCPMessageSize];
                callerConnection.SIPStream.BeginRead(callerConnection.SocketBuffer, 0, MaxSIPTCPMessageSize, new AsyncCallback(ReceiveCallback), callerConnection);

                logger.Debug("Established TLS connection to " + callerConnection.RemoteEndPoint + ".");

                callerConnection.SIPStream.BeginWrite(buffer, 0, buffer.Length, EndSend, new object[]{callerConnection, onSendDone});
            }
            catch (Exception excp)
            {
                onSendDone?.Invoke(false);

                FinishJobAndStartNextOne(dstEndPoint);
                logger.Error("Exception SIPTLSChannel EndAuthenticateAsClient. BeginRead/BeginWrite" + excp);
                m_logError?.Invoke("Exception SIPTLSChannel EndAuthenticateAsClient. BeginRead/BeginWrite" + excp);
            }
        }


        private void ExecuteJobOrQueueIt(string a_endpointKey, ITlsChannelJob a_job)
        {
            bool execute;
            lock (m_connectAndSendSync)
            {
                if (Closed)
                {
                    a_job.Abort();
                    return;
                }

                Queue<ITlsChannelJob> endpointQueue;

                if (!m_endpointJobLists.TryGetValue(a_endpointKey, out endpointQueue))
                {
                    endpointQueue = new Queue<ITlsChannelJob>();
                    m_endpointJobLists.Add(a_endpointKey, endpointQueue);
                }

                execute = endpointQueue.Count == 0;
                endpointQueue.Enqueue(a_job);
            }
            if (execute)
                a_job.Execute();
        }

        private void FinishJobAndStartNextOne(IPEndPoint a_dstEndPoint)
        {
            ITlsChannelJob nextJob = null;
            lock (m_connectAndSendSync)
            {
                if (!m_endpointJobLists.TryGetValue(a_dstEndPoint.ToString(), out var endpointQueue)
                    || (endpointQueue.Count == 0))
                    return;

                endpointQueue.Dequeue();
                if (endpointQueue.Count != 0)
                    nextJob = endpointQueue.Peek();
            }

            if (Closed)
                return;

            if (nextJob != null)
            {
                Task.Run(nextJob.Execute);
            }
        }



        protected override Dictionary<string, SIPConnection> GetConnectionsList()
        {
            return m_connectedSockets;
        }

        public override bool IsConnectionEstablished(IPEndPoint remoteEndPoint)
        {
            lock (m_connectedSockets)
            {
                return m_connectedSockets.ContainsKey(remoteEndPoint.ToString());
            }
        }

        private void SIPTLSSocketDisconnected(IPEndPoint remoteEndPoint)
        {
            SIPConnection closedConnection = null;
            try
            {
                logger.Debug("TLS socket from " + remoteEndPoint + " disconnected.");
                var key = remoteEndPoint.ToString();

                lock (m_connectAndSendSync)
                {
                    if (m_endpointJobLists.TryGetValue(key, out var endpointQueue))
                    {
                        while (endpointQueue.Count != 0)
                        {
                            var job = endpointQueue.Dequeue();
                            job.Abort();
                        }

                        m_endpointJobLists.Remove(key);
                    }
                }

                lock (m_connectedSockets)
                {
                    m_connectedSockets.TryGetValue(key, out closedConnection);
                    m_connectedSockets.Remove(key);
                    m_connectingSockets.Remove(key);
                }
            }
            catch (Exception excp)
            {
                logger.Error("Exception SIPTLSClientDisconnected. " + excp);
            }

            if (null != closedConnection)
                FireConnectionClosed(closedConnection);
        }

        private void SIPTLSMessageReceived(SIPChannel channel, SIPEndPoint remoteEndPoint, byte[] buffer)
        {
            if (SIPMessageReceived != null)
            {
                SIPMessageReceived(channel, remoteEndPoint, buffer);
            }
        }

        private X509Certificate GetServerCert()
        {
            //X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            X509Store store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509CertificateCollection cert = store.Certificates.Find(X509FindType.FindBySubjectName, "10.0.0.100", true);
            return cert[0];
        }

        private void DisplayCertificateChain(X509Certificate2 certificate)
        {
            X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            ch.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            ch.Build(certificate);
            Console.WriteLine("Chain Information");
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);
            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
        }

        private void DisplaySecurityLevel(SslStream stream)
        {
            logger.Debug(String.Format("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength));
            logger.Debug(String.Format("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength));
            logger.Debug(String.Format("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength));
            logger.Debug(String.Format("Protocol: {0}", stream.SslProtocol));
        }

        private void DisplaySecurityServices(SslStream stream)
        {
            logger.Debug(String.Format("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer));
            logger.Debug(String.Format("IsSigned: {0}", stream.IsSigned));
            logger.Debug(String.Format("Is Encrypted: {0}", stream.IsEncrypted));
        }

        private void DisplayStreamProperties(SslStream stream)
        {
            logger.Debug(String.Format("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite));
            logger.Debug(String.Format("Can timeout: {0}", stream.CanTimeout));
        }

        private void DisplayCertificateInformation(SslStream stream)
        {
            logger.Debug(String.Format("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus));

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                logger.Debug(String.Format("Local cert was issued to {0} and is valid from {1} until {2}.",
                     localCertificate.Subject,
                     localCertificate.GetEffectiveDateString(),
                     localCertificate.GetExpirationDateString()));
            }
            else
            {
                logger.Warn("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                logger.Debug(String.Format("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString()));
            }
            else
            {
                logger.Warn("Remote certificate is null.");
            }
        }

        private bool InboundCertificateValidation(
            SIPTLSChannel channel,
            IPEndPoint remotEndPoint,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }
            else
            {
                logger.Warn(String.Format("Certificate error: {0}", sslPolicyErrors));
                return true;
            }
        }

        private bool OutboundCertificateValidation(
            SIPTLSChannel channel,
            IPEndPoint remotEndPoint,
            string serverFQDN,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }
            else
            {
                logger.Warn(String.Format("Certificate error: {0}", sslPolicyErrors));
                return true;
            }
        }


        public override void Close()
        {
            if (!Closed == true)
            {
                logger.Debug("Closing SIP TLS Channel " + SIPChannelEndPoint + ".");
                m_logDebug?.Invoke("Closing SIP TLS Channel " + SIPChannelEndPoint + ".");

                Closed = true;

                lock (m_connectAndSendSync)
                {
                    foreach (var endpointJobList in m_endpointJobLists)
                    {
                        while (endpointJobList.Value.Count != 0)
                        {
                            var job = endpointJobList.Value.Dequeue();
                            job.Abort();
                        }
                    }
                }

                lock (m_connectedSockets)
                {
                    foreach (SIPConnection tcpConnection in m_connectedSockets.Values)
                    {
                        FireConnectionClosed(tcpConnection);
                        try
                        {
                            tcpConnection.Close();
                        }
                        catch (Exception connectionCloseExcp)
                        {
                            m_logError?.Invoke($"SIPTLSChannel.Close Exception: {connectionCloseExcp}");
                            logger.Warn("Exception SIPTLSChannel Close (shutting down connection to " + tcpConnection.RemoteEndPoint + "). " + connectionCloseExcp.Message);
                        }
                    }

                    m_connectedSockets.Clear();
                }

                try
                {
                    m_tlsServerListener.Stop();
                    if (!m_tlsServerListenerThread.Join(TimeSpan.FromSeconds(LINGER_TIMEOUT + 1)))
                    {
                        m_logError?.Invoke($"SIPTLSChannel Close (shutting down listener). Listener thread doesn't stop within {LINGER_TIMEOUT} seconds.");
                        logger.Warn($"SIPTLSChannel Close (shutting down listener). Listener thread doesn't stop within {LINGER_TIMEOUT} seconds.");
                        m_tlsServerListenerThread.Abort();
                    }
                }
                catch (Exception listenerCloseExcp)
                {
                    m_logError?.Invoke("Exception SIPTLSChannel Close (shutting down listener). " + listenerCloseExcp.Message);
                    logger.Warn("Exception SIPTLSChannel Close (shutting down listener). " + listenerCloseExcp.Message);
                }
            }
        }

        private void FireConnectionClosed(SIPConnection closedConnection)
        {
            try
            {
                ConnectionClosed?.Invoke(this,closedConnection);
            }
            catch
            {
            }
        }

        private void FireConnectionOpened(SIPConnection openedConnection)
        {
            try
            {
                ConnectionOpened?.Invoke(this, openedConnection);
            }
            catch
            {
            }
        }


        private void Dispose(bool disposing)
        {
            try
            {
                this.Close();
            }
            catch (Exception excp)
            {
                logger.Error("Exception Disposing SIPTLSChannel. " + excp.Message);
            }
        }
    }
}
