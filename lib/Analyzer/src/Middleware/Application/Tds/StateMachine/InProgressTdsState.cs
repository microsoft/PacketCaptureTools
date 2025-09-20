// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;

/// <summary>
/// InProgress TDS connection state.
/// </summary>
/// <inheritdoc />
internal abstract class InProgressTdsState(IPacketFlowDetector packetFlowDetector) : TdsState(packetFlowDetector)
{

    /// <inheritdoc />
    protected override TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (segment.Flags.Fin ||
            segment.Flags.Rst)
        {
            return new ConnectionClosedWithErrorTdsState(PacketFlowDetector);
        }

        return GetNextInProgressTdsState(segment, tdsMessage, tlsRecord);
    }

    /// <summary>
    /// Get next <see cref="TdsState" /> based on <see cref="TcpSegment" /> flags and payload.
    /// </summary>
    /// <param name="ipPacket">IP packet.</param>
    /// <param name="segment">TCP segment.</param>
    /// <param name="tdsMessage">TDS message.</param>
    /// <param name="tlsRecord">TLS record.</param>
    /// <returns>Next <see cref="TdsState" />.</returns>
    protected abstract TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default);
}
