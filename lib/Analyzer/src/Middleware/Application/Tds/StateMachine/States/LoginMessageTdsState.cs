// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol login message sent state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="LoginMessageTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class LoginMessageTdsState(IPacketFlowDetector packetFlowDetector) : InProgressTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.LoginMessage;

    /// <inheritdoc />
    protected override TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tlsRecord is not null &&
            tlsRecord.ContentType == ContentType.Application &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new LoginAckTdsState(PacketFlowDetector);
        }

        // change state based on assumption
        if ((segment.Flags.Psh || (segment.Flags.Ack && segment.NonTruncatedPayloadLength > 0)) &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new LoginAckTdsState(PacketFlowDetector);
        }

        return this;
    }
}
