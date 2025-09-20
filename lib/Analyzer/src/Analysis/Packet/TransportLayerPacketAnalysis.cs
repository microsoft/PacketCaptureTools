// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet;

/// <summary>
/// Transport layer individual packet analysis.
/// </summary>
public abstract class TransportLayerPacketAnalysis : IPacketAnalysis
{
    /// <inheritdoc />
    public void Process(CapturedPacket packet)
    {
        if (packet != null &&
            packet?.NetworkPacket is IpPacket ipPacket &&
            packet?.TransportSegment != null)
        {
            Process(packet, ipPacket, packet.TransportSegment);
        }
    }

    /// <summary>
    /// Perform analysis on transport layer packet.
    /// </summary>
    /// <param name="packet">Captured packet containing data and time of capture.</param>
    /// <param name="ipPacket">The IP packet containing information on source and destination addresses.</param>
    /// <param name="segment">The transport segment from the captured packet.</param>
    public abstract void Process(CapturedPacket packet, IpPacket ipPacket, TransportSegment segment);
}
