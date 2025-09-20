// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet;

/// <summary>
/// Metrics for packet counter analysis per IP.
/// </summary>
public class PerIpCounterMetrics
{
    /// <summary>
    /// Gets or sets the counter for total packets for the IP.
    /// </summary>
    public int TotalPacketCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for TCP packets for the IP.
    /// </summary>
    public int TcpPacketCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for Tds packets for the IP.
    /// </summary>
    public int TdsPacketCount { get; set; }
}
