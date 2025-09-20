// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;

/// <summary>
/// Base class of a TCP connection state machine.
/// </summary>
internal abstract class TcpState
{
    /// <summary>
    /// Gets TCP connection state.
    /// </summary>
    internal abstract TcpConnectionState TcpConnectionState { get; }

    /// <summary>
    /// Get next <see cref="TcpState" /> based on <see cref="TcpFlags" />.
    /// </summary>
    /// <param name="tcpFlags">TCP flags.</param>
    /// <returns>next <see cref="TcpState" />.</returns>
    internal TcpState GetNextState(TcpFlags tcpFlags)
    {
        if (tcpFlags.Rst)
        {
            return new ClosedTcpState();
        }

        if (tcpFlags.Syn &&
            tcpFlags.Fin)
        {
            return this;
        }

        return GetNextTcpState(tcpFlags);
    }

    /// <summary>
    /// Get next <see cref="TcpState" /> based on <see cref="TcpFlags" />.
    /// </summary>
    /// <param name="tcpFlags">TCP flags.</param>
    /// <returns>next <see cref="TcpState" />.</returns>
    protected abstract TcpState GetNextTcpState(TcpFlags tcpFlags);
}
