// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// Unknown TDS connection state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="UnknownTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class UnknownTdsState(IPacketFlowDetector packetFlowDetector) : FinalTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.Unknown;

    protected override TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (tdsMessage != null &&
            tlsRecord == null &&
            tdsMessage.Type == TdsMessageType.PreLogin)
        {
            if (PacketDirection == PacketDirection.Incoming)
            {
                return new PreLoginTdsState(PacketFlowDetector);
            }

            return new PreLoginResponseTdsState(PacketFlowDetector);
        }

        if (segment.Flags.Psh &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new PreLoginTdsState(PacketFlowDetector);
        }

        return base.GetNextTdsState(segment, tdsMessage, tlsRecord);
    }
}
