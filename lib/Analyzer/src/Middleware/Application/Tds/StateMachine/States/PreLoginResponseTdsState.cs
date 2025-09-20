// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol pre-login response state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="PreLoginResponseTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class PreLoginResponseTdsState(IPacketFlowDetector packetFlowDetector) : TdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.PreLoginResponse;

    /// <inheritdoc />
    protected override TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tlsRecord != null &&
            tlsRecord.IsHandshake &&
            tlsRecord.MessageType == MessageType.ClientHello &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new ClientHelloTdsState(PacketFlowDetector);
        }

        // change state based on assumption
        if (segment.Flags.Psh &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new ClientHelloTdsState(PacketFlowDetector);
        }

        return this;
    }
}
