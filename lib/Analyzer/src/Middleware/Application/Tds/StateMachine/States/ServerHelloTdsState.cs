// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol TLS handshake server-hello state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ServerHelloTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class ServerHelloTdsState(IPacketFlowDetector packetFlowDetector) : InProgressTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.ServerHello;

    /// <inheritdoc />
    protected override TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tlsRecord != null &&
            PacketDirection == PacketDirection.Incoming)
        {
            if (tlsRecord.IsHandshake &&
                tlsRecord.MessageType == MessageType.ClientKeyExchange)
            {
                return new KeyExchangeTdsState(PacketFlowDetector);
            }

            if (tlsRecord.ContentType == ContentType.ChangeCipherSpec)
            {
                return new CipherChangeTdsState(PacketFlowDetector);
            }
        }

        // change state based on assumption
        if (segment.Flags.Psh &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new KeyExchangeTdsState(PacketFlowDetector);
        }

        return this;
    }
}
