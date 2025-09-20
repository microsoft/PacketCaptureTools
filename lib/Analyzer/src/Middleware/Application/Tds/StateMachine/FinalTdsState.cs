// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;

/// <summary>
/// Unknown TDS connection state.
/// </summary>
/// <inheritdoc />
internal abstract class FinalTdsState(IPacketFlowDetector packetFlowDetector) : TdsState(packetFlowDetector)
{

    /// <inheritdoc />
    protected override TdsState GetNextTdsState(TcpSegment segment, TdsMessage? tdsMessage = default, TlsRecord? tlsRecord = default)
    {
        if (segment.Flags.Syn &&
            PacketDirection == PacketDirection.Incoming)
        {
            return new TcpHandshakeTdsState(PacketFlowDetector);
        }

        return this;
    }
}
