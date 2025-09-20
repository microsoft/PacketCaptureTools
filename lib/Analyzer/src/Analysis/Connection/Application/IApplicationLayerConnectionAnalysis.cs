// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;

/// <summary>
/// Application layer specific analysis.
/// </summary>
public interface IApplicationLayerConnectionAnalysis
{
    /// <summary>
    /// Processes the transport layer packet headers for analysis.
    /// </summary>
    /// <param name="packet">Captured packet containing data and time of capture.</param>
    /// <param name="applicationConnectionSnapshot">The application layer connection snapshot.</param>
    void Process(CapturedPacket packet, ApplicationConnectionSnapshot applicationConnectionSnapshot);
}
