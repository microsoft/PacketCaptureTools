// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;

/// <summary>
/// TCP state class representing a second finish sent TCP state of a TCP connection state machine.
/// </summary>
internal class SecondFinishSentTcpState : TcpStateForEstablishedConnection
{
    /// <inheritdoc />
    internal override TcpConnectionState TcpConnectionState => TcpConnectionState.SecondFinishSent;

    /// <inheritdoc />
    protected override TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags)
    {
        if (tcpFlags.Ack)
        {
            return new ClosedTcpState();
        }

        return this;
    }
}
