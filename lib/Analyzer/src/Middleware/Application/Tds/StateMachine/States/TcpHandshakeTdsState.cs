// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// The TCP handshake state of a TDS connection.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TcpHandshakeTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class TcpHandshakeTdsState(IPacketFlowDetector packetFlowDetector) : InProgressTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.TcpHandshake;

    /// <inheritdoc />
    protected override TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tdsMessage != null &&
            tlsRecord == null &&
            tdsMessage.Type == TdsMessageType.PreLogin &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new PreLoginTdsState(PacketFlowDetector);
        }

        if (segment.Flags.Psh &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new PreLoginTdsState(PacketFlowDetector);
        }

        return this;
    }
}
