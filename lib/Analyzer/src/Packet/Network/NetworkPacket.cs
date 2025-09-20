// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network;

/// <summary>
/// A network packet.
/// </summary>
public abstract class NetworkPacket
{
    /// <summary>
    /// Gets the packet header type.
    /// </summary>
    public virtual NetworkPacketProtocol Protocol { get; }

    /// <summary>
    /// Gets the senders IP address.
    /// </summary>
    public abstract IPAddress SourceAddress { get; }

    /// <summary>
    /// Gets the receiver IP address.
    /// </summary>
    public abstract IPAddress DestinationAddress { get; }

    /// <summary>
    /// Gets the transport segment which the packet contains. Can be <c>null</c> when the transport protocol data is unrecognized or not present.
    /// </summary>
    public virtual TransportSegment? TransportSegment { get; }
}
