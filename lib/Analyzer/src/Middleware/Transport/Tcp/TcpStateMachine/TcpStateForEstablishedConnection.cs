// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;

/// <summary>
/// Base class for TCP states with established TCP connection.
/// </summary>
internal abstract class TcpStateForEstablishedConnection : TcpState
{
    /// <inheritdoc />
    protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
    {
        if (tcpFlags.Syn)
        {
            return this;
        }

        return GetNextTcpStateForEstablishedConnection(tcpFlags);
    }

    /// <summary>
    /// Get next <see cref="TcpState" /> for an already-established connection based on <see cref="TcpFlags" />.
    /// </summary>
    /// <param name="tcpFlags">TCP flags.</param>
    /// <returns>next <see cref="TcpState" />.</returns>
    protected abstract TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags);
}
