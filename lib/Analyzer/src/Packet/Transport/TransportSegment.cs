// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Transport;

/// <summary>
/// A transport layer segment.
/// </summary>
public abstract class TransportSegment
{
    /// <summary>
    /// Gets the transport segment protocol.
    /// </summary>
    public virtual TransportSegmentProtocol Protocol { get; }

    /// <summary>
    /// Gets the source sender port.
    /// </summary>
    public virtual int SourcePort { get; }

    /// <summary>
    /// Gets the destination receiver port.
    /// </summary>
    public virtual int DestinationPort { get; }

    /// <summary>
    /// Gets the transport segment payload.
    /// </summary>
    public abstract byte[] Payload { get; }
}
