// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol TLS handshake key exchange state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="KeyExchangeTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class KeyExchangeTdsState(IPacketFlowDetector packetFlowDetector) : InProgressTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.KeyExchange;

    /// <inheritdoc />
    protected override TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tlsRecord is not null &&
            tlsRecord.ContentType == ContentType.ChangeCipherSpec &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new CipherChangeTdsState(PacketFlowDetector);
        }

        // change state based on assumption
        if ((segment.Flags.Psh || (segment.Flags.Ack && segment.NonTruncatedPayloadLength > 0)) &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new CipherChangeTdsState(PacketFlowDetector);
        }

        return this;
    }
}
