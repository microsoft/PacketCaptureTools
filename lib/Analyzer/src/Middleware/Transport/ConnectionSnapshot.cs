// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Transport;

/// <summary>
/// Network connection snapshot.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ConnectionSnapshot" /> class.
/// </remarks>
/// <param name="transportConnection">The transport layer connection.</param>
public abstract class ConnectionSnapshot(TransportLayerConnection transportConnection)
{

    /// <summary>
    /// Gets the transport layer connection.
    /// </summary>
    public TransportLayerConnection TransportConnection { get; } = transportConnection ?? throw new ArgumentNullException(nameof(transportConnection));
}
