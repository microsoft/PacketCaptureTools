// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing a first finish acknowledged TCP state of the TCP connection state machine.
    /// </summary>
    internal class FirstFinishAcknowledgedTcpState : TcpStateForEstablishedConnection
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.FirstFinishAcknowledged;

        /// <inheritdoc />
        protected override TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags)
        {
            if (tcpFlags.Fin)
            {
                return new SecondFinishSentTcpState();
            }

            return this;
        }
    }
}
