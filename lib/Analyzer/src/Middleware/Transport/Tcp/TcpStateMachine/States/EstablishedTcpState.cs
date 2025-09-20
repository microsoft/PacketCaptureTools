// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing an established TCP state of a TCP connection state machine.
    /// </summary>
    internal class EstablishedTcpState : TcpStateForEstablishedConnection
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.Established;

        /// <inheritdoc />
        protected override TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags)
        {
            if (tcpFlags.Fin)
            {
                return new FirstFinishSentTcpState();
            }

            return this;
        }
    }
}
