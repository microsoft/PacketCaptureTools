// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing an unknown TCP state of a TCP connection state machine.
    /// </summary>
    internal class UnknownTcpState : TcpState
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.Unknown;

        /// <inheritdoc />
        protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
        {
            if (tcpFlags.Syn &&
                !tcpFlags.Ack)
            {
                return new SynSentTcpState();
            }

            if (tcpFlags.Syn &&
                tcpFlags.Ack)
            {
                return new SynAcknowledgedTcpState();
            }

            if (tcpFlags.Fin &&
                tcpFlags.Ack)
            {
                return new ClosedTcpState();
            }

            if (tcpFlags.Ack)
            {
                return new AssumedEstablishedTcpState();
            }

            return this;
        }
    }
}
