// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing a first finish sent TCP state of the TCP connection state machine.
    /// </summary>
    internal class FirstFinishSentTcpState : TcpStateForEstablishedConnection
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.FirstFinishSent;

        /// <inheritdoc />
        protected override TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags)
        {
            if (tcpFlags.Ack &&
                !tcpFlags.Fin)
            {
                return new FirstFinishAcknowledgedTcpState();
            }

            if (tcpFlags.Ack &&
                tcpFlags.Fin)
            {
                return new SecondFinishSentTcpState();
            }

            return this;
        }
    }
}
