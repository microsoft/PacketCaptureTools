// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol pre-login state.
/// </summary>
internal class PreLoginTdsState : InProgressTdsState
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PreLoginTdsState" /> class.
    /// </summary>
    /// <param name="packetFlowDetector">Packet flow detector.</param>
    public PreLoginTdsState(IPacketFlowDetector packetFlowDetector)
        : base(packetFlowDetector)
    {
    }

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.PreLogin;

    /// <inheritdoc />
    protected override TdsState GetNextInProgressTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tdsMessage != null &&
            tlsRecord == null &&
            tdsMessage.Type == TdsMessageType.ServerResponse &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new PreLoginResponseTdsState(PacketFlowDetector);
        }

        // change state based on assumption
        if ((segment.Flags.Psh || (segment.Flags.Ack && segment.NonTruncatedPayloadLength > 0)) &&
            PacketDirection == PacketDirection.Outgoing)
        {
            return new PreLoginResponseTdsState(PacketFlowDetector);
        }

        return this;
    }
}
