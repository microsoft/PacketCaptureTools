// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application;

/// <summary>
/// An application layer connection snapshot.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ApplicationConnectionSnapshot" /> class.
/// </remarks>
/// <param name="transportSegment">The transport layer segment.</param>
/// <param name="transportConnectionSnapshot">The transport layer connection snapshot.</param>
public abstract class ApplicationConnectionSnapshot(
    TransportSegment transportSegment,
    TransportConnectionSnapshot transportConnectionSnapshot) : ConnectionSnapshot(transportConnectionSnapshot.TransportConnection)
{

    /// <summary>
    /// Gets the transport layer segment containing application connection payload.
    /// </summary>
    public TransportSegment TransportSegment { get; } = transportSegment;

    /// <summary>
    /// Gets the transport layer connection snapshot.
    /// </summary>
    public TransportConnectionSnapshot TransportConnectionSnapshot { get; } = transportConnectionSnapshot;
}
