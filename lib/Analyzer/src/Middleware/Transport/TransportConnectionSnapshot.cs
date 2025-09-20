// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using System;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport;

/// <summary>
/// Transport layer connection snapshot.
/// </summary>
public abstract class TransportConnectionSnapshot : ConnectionSnapshot
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TransportConnectionSnapshot" /> class.
    /// </summary>
    /// <param name="transportConnection">The transport layer connection.</param>
    /// <param name="packetFlowDetector">Packet flow detector, with respect to the node on which the capture was triggered.</param>
    protected TransportConnectionSnapshot(
        TransportLayerConnection transportConnection,
        IPacketFlowDetector packetFlowDetector)
        : base(transportConnection)
    {
        PacketFlowDetector = packetFlowDetector ?? throw new ArgumentNullException(nameof(packetFlowDetector));
    }

    /// <summary>
    /// Gets the packet flow detector.
    /// </summary>
    internal IPacketFlowDetector PacketFlowDetector { get; }
}
