// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet;

/// <summary>
/// Packet analysis.
/// </summary>
public interface IPacketAnalysis
{
    /// <summary>
    /// Processes a Packet for analysis.
    /// </summary>
    /// <param name="packet">Packet Abstract class to be processed.</param>
    void Process(CapturedPacket packet);
}
