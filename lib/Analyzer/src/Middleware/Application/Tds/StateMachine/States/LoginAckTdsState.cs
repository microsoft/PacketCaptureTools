// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;

/// <summary>
/// TDS protocol login message acknowledged state.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="LoginAckTdsState" /> class.
/// </remarks>
/// <param name="packetFlowDetector">Packet flow detector.</param>
internal class LoginAckTdsState(IPacketFlowDetector packetFlowDetector) : FinalTdsState(packetFlowDetector)
{

    /// <inheritdoc />
    internal override TdsConnectionState TdsConnectionState => TdsConnectionState.LoginAck;

    protected override TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (segment.Flags.Fin ||
            segment.Flags.Rst)
        {
            return new ConnectionClosedAfterLoginAckTdsState(PacketFlowDetector);
        }

        return base.GetNextTdsState(segment, tdsMessage, tlsRecord);
    }
}
