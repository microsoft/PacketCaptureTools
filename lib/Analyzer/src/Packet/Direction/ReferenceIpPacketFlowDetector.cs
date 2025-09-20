// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Packet.Direction;

/// <summary>
/// Detects the flow direction of a given packet, based on a set of reference IP addresses.
/// </summary>
public class ReferenceIpPacketFlowDetector : IPacketFlowDetector
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReferenceIpPacketFlowDetector" /> class.
    /// </summary>
    /// <param name="referenceIpAddresses">Reference IP Addresses.</param>
    public ReferenceIpPacketFlowDetector(IEnumerable<IPAddress> referenceIpAddresses)
    {
        if (referenceIpAddresses == null || !referenceIpAddresses.Any())
        {
            throw new ArgumentException($"Reference Ip Addresses cannot be null or empty.", nameof(referenceIpAddresses));
        }

        ReferenceIpAddresses = new HashSet<IPAddress>(referenceIpAddresses);
    }

    /// <summary>
    /// Gets the IP addresses assigned to the NIC(s) on the capture machine. Packets originating from these IP addresses will be deemed as outgoing.
    /// </summary>
    public IEnumerable<IPAddress> ReferenceIpAddresses { get; }

    /// <inheritdoc/>
    public PacketDirection GetCapturedPacketDirection(CapturedPacket packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        ArgumentNullException.ThrowIfNull(packet.NetworkPacket);

        return GetNetworkPacketDirection(packet.NetworkPacket);
    }

    /// <inheritdoc/>
    public PacketDirection GetNetworkPacketDirection(NetworkPacket packet)
    {
        ArgumentNullException.ThrowIfNull(packet);

        if (ReferenceIpAddresses.Contains(packet.SourceAddress))
        {
            return PacketDirection.Outgoing;
        }

        if (ReferenceIpAddresses.Contains(packet.DestinationAddress))
        {
            return PacketDirection.Incoming;
        }

        return PacketDirection.Unknown;
    }
}

