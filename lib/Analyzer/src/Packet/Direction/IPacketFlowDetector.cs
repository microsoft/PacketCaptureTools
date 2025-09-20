// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Network;

namespace Microsoft.PacketCapture.Analyzer.Packet.Direction;

/// <summary>
/// Determines the flow direction of individual packets.
/// </summary>
public interface IPacketFlowDetector
{
    /// <summary>
    /// Determines the direction of a given captured packet.
    /// </summary>
    /// <param name="packet">Captured packet.</param>
    /// <returns>The flow direction of the packet as a <see cref="PacketDirection" /> enum.</returns>
    PacketDirection GetCapturedPacketDirection(CapturedPacket packet);

    /// <summary>
    /// Determines the direction of a given network packet.
    /// </summary>
    /// <param name="packet">Network packet.</param>
    /// <returns>The flow direction of the packet as a <see cref="PacketDirection" /> enum.</returns>
    PacketDirection GetNetworkPacketDirection(NetworkPacket packet);
}

