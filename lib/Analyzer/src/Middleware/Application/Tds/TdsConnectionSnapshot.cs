// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;

/// <summary>
/// TDS protocol connection snapshot.
/// </summary>
public class TdsConnectionSnapshot : ApplicationConnectionSnapshot
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionSnapshot" /> class.
    /// </summary>
    /// <param name="ipPacket">IP packet.</param>
    /// <param name="segment">Transport layer segment.</param>
    /// <param name="tcpConnectionSnapshot">TCP connection snapshot.</param>
    /// <param name="tdsMessage">Optional. TDS message.</param>
    /// <param name="tlsRecord">Optional. TLS record.</param>
    internal TdsConnectionSnapshot(
        IpPacket ipPacket,
        TcpSegment segment,
        TcpConnectionSnapshot tcpConnectionSnapshot,
        TdsMessage? tdsMessage = default,
        TlsRecord? tlsRecord = default)
        : base(segment, tcpConnectionSnapshot)
    {
        State = new UnknownTdsState(tcpConnectionSnapshot.PacketFlowDetector).GetNextTdsState(ipPacket, segment, tdsMessage, tlsRecord);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionSnapshot" /> class.
    /// </summary>
    /// <param name="segment">The TCP segment.</param>
    /// <param name="tcpConnectionSnapshot">TCP connection snapshot.</param>
    /// <param name="state">The TDS connection state.</param>
    internal TdsConnectionSnapshot(
        TcpSegment segment,
        TcpConnectionSnapshot tcpConnectionSnapshot,
        TdsState state)
        : base(segment, tcpConnectionSnapshot)
    {
        State = state;
    }

    /// <summary>
    /// Gets the TDS connection state of this snapshot.
    /// </summary>
    public TdsConnectionState TdsConnectionState => State.TdsConnectionState;

    /// <summary>
    /// Gets the TDS state for this snapshot.
    /// </summary>
    internal TdsState State { get; private set; }

    /// <summary>
    /// Gets the TCP connection snapshot.
    /// </summary>
    internal TcpConnectionSnapshot TcpConnectionSnapshot => (TcpConnectionSnapshot)TransportConnectionSnapshot;

    /// <summary>
    /// Updates the current TDS connection snapshot state.
    /// </summary>
    /// <param name="ipPacket">The IP packet.</param>
    /// <param name="segment">The transport layer segment.</param>
    /// <param name="tdsMessage">Optional. TDS message.</param>
    /// <param name="tlsRecord">Optional. TLS record.</param>
    internal virtual void UpdateTdsConnectionSnapshot(
        IpPacket? ipPacket,
        TransportSegment? segment,
        TdsMessage? tdsMessage = default,
        TlsRecord? tlsRecord = default)
    {
        if (segment is TcpSegment tcpSegment)
        {
            State = State.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, tlsRecord);
        }
    }
}
