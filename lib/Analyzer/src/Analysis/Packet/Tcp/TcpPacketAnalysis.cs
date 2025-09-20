// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;

/// <summary>
/// TCP packet analysis.
/// </summary>
public abstract class TcpPacketAnalysis : TransportLayerPacketAnalysis
{
    /// <inheritdoc />
    public override void Process(CapturedPacket packet, IpPacket ipPacket, TransportSegment segment)
    {
        if (segment is TcpSegment tcpSegment)
        {
            Process(packet, ipPacket, tcpSegment);
        }
    }

    /// <summary>
    /// Perform analysis on individual TCP packet.
    /// </summary>
    /// <param name="packet">Captured packet containing data and time of capture.</param>
    /// <param name="ipPacket">Network layer IP packet containing information on source and destination addresses.</param>
    /// <param name="tcpSegment">TCP segment from capture.</param>
    public abstract void Process(CapturedPacket packet, IpPacket ipPacket, TcpSegment tcpSegment);
}
