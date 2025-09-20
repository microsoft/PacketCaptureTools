// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing a closed TCP state of a TCP connection state machine.
    /// </summary>
    internal class ClosedTcpState : TcpState
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.Closed;

        /// <inheritdoc />
        protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
        {
            if (tcpFlags.Syn)
            {
                return new SynSentTcpState();
            }

            return this;
        }
    }
}
