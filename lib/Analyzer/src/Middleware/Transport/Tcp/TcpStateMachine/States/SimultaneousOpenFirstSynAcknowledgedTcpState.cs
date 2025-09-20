// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States
{
    /// <summary>
    /// TCP state class representing a simultaneous open first syn acknowledged TCP state of a TCP connection state machine.
    /// </summary>
    internal class SimultaneousOpenFirstSynAcknowledgedTcpState : TcpState
    {
        /// <inheritdoc />
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.SimultaneousOpenFirstSynAcknowledged;

        /// <inheritdoc />
        protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
        {
            if (tcpFlags.Syn &&
                tcpFlags.Ack)
            {
                return new EstablishedTcpState();
            }

            return this;
        }
    }
}
