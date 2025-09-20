// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application;

/// <summary>
/// Application layer connection middleware.
/// </summary>
public interface IApplicationConnectionMiddleware
{
    /// <summary>
    /// Create a snapshot of the application layer connection.
    /// </summary>
    /// <param name="capturedPacket">The captured packet.</param>
    /// <param name="transportConnectionSnapshot">The transport layer connection snapshot.</param>
    /// <returns>An application layer connection snapshot.</returns>
    ApplicationConnectionSnapshot? Process(CapturedPacket capturedPacket, TransportConnectionSnapshot transportConnectionSnapshot);
}
