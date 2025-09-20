// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;

/// <summary>
/// TDS connection state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal abstract class TdsState(IPacketFlowDetector packetFlowDetector)
{

    /// <summary>
    /// Gets the packet flow detector.
    /// </summary>
    internal IPacketFlowDetector PacketFlowDetector { get; } = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));

    /// <summary>
    /// Gets the packet direction.
    /// </summary>
    internal PacketDirection PacketDirection { get; private set; }

    /// <summary>
    /// Gets the current state of the TDS connection.
    /// </summary>
    internal abstract TdsConnectionState TdsConnectionState { get; }

    /// <summary>
    /// Get next <see cref="TdsState" /> based on <see cref="TcpSegment" /> flags and payload.
    /// </summary>
    /// <param name="ipPacket">IP packet.</param>
    /// <param name="segment">TCP segment.</param>
    /// <param name="tdsMessage">TDS message.</param>
    /// <param name="tlsRecord">TLS record.</param>
    /// <returns>next <see cref="TdsState" />.</returns>
    internal TdsState GetNextTdsState(
        IpPacket? ipPacket,
        TcpSegment? segment,
        TdsMessage? tdsMessage,
        TlsRecord? tlsRecord)
    {
        if (ipPacket is null ||
            segment is null)
        {
            return this;
        }

        PacketDirection = PacketFlowDetector.GetNetworkPacketDirection(ipPacket);

        return GetNextTdsState(segment, tdsMessage, tlsRecord);
    }

    /// <summary>
    /// Get next <see cref="TdsState" /> based on <see cref="TcpSegment" /> flags and payload.
    /// </summary>
    /// <param name="segment">TCP segment.</param>
    /// <param name="tdsMessage">TDS message.</param>
    /// <param name="tlsRecord">TLS record.</param>
    /// <returns>Next <see cref="TdsState" />.</returns>
    protected abstract TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default);
}
