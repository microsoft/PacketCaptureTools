// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;

/// <summary>
/// Transport layer specific analysis.
/// </summary>
public interface ITransportLayerConnectionAnalysis
{
    /// <summary>
    /// Processes the transport layer packet headers for analysis.
    /// </summary>
    /// <param name="packet">Captured packet containing data and time of capture.</param>
    /// <param name="transportConnectionSnapshot">The transport connection snapshot.</param>
    void Process(CapturedPacket packet, TransportConnectionSnapshot transportConnectionSnapshot);
}
