// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP
{
    /// <summary>
    /// TCP flags consisting of 9 1-bit control flags.
    /// </summary>
    public class TcpFlags
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TcpFlags" /> class.
        /// </summary>
        /// <param name="bitValue">Tcp flags value.</param>
        public TcpFlags(int bitValue)
        {
            Ns = (bitValue & 256) == 256;
            Cwr = (bitValue & 128) == 128;
            Ece = (bitValue & 64) == 64;
            Urg = (bitValue & 32) == 32;
            Ack = (bitValue & 16) == 16;
            Psh = (bitValue & 8) == 8;
            Rst = (bitValue & 4) == 4;
            Syn = (bitValue & 2) == 2;
            Fin = (bitValue & 1) == 1;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TcpFlags" /> class.
        /// </summary>
        /// <param name="ns">NS flag value.</param>
        /// <param name="cwr">CWR flag value.</param>
        /// <param name="ece">ECE flag value.</param>
        /// <param name="urg">URG flag value.</param>
        /// <param name="ack">ACK flag value.</param>
        /// <param name="psh">PSH flag value.</param>
        /// <param name="rst">RST flag value.</param>
        /// <param name="syn">SYN flag value.</param>
        /// <param name="fin">FIN flag value.</param>
        public TcpFlags(
            bool ns = false,
            bool cwr = false,
            bool ece = false,
            bool urg = false,
            bool ack = false,
            bool psh = false,
            bool rst = false,
            bool syn = false,
            bool fin = false)
        {
            Ns = ns;
            Cwr = cwr;
            Ece = ece;
            Urg = urg;
            Ack = ack;
            Psh = psh;
            Rst = rst;
            Syn = syn;
            Fin = fin;
        }

        /// <summary>
        /// Gets a value indicating whether Explicit Congestion Notification is enabled.
        /// </summary>
        public bool Ns { get; }

        /// <summary>
        /// Gets a value indicating whether Congestion Window Reduced is enabled.
        /// </summary>
        public bool Cwr { get; }

        /// <summary>
        /// Gets a value indicating whether Explicit Congestion Notification Echo is enabled.
        /// </summary>
        public bool Ece { get; }

        /// <summary>
        /// Gets a value indicating whether the packet is marked as Urgent.
        /// </summary>
        public bool Urg { get; }

        /// <summary>
        /// Gets a value indicating whether the Acknowledgment field is significant.
        /// </summary>
        public bool Ack { get; }

        /// <summary>
        /// Gets a value indicating whether to push the buffered data to the receiving application.
        /// </summary>
        public bool Psh { get; }

        /// <summary>
        /// Gets a value indicating whether to reset the connection.
        /// </summary>
        public bool Rst { get; }

        /// <summary>
        /// Gets a value indicating whether to synchronize the sequence numbers.
        /// </summary>
        public bool Syn { get; }

        /// <summary>
        /// Gets a value indicating whether this is the last packet from the sender.
        /// </summary>
        public bool Fin { get; }
    }
}
