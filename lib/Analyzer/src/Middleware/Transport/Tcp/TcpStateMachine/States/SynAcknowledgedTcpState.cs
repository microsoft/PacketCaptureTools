// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing a syn acknowledged TCP state of a TCP connection state machine.
    /// </summary>
    internal class SynAcknowledgedTcpState : TcpState
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.SynAcknowledged;

        /// <inheritdoc />
        protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
        {
            if (tcpFlags.Ack)
            {
                return new EstablishedTcpState();
            }

            return this;
        }
    }
}
