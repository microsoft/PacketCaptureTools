// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;

/// <summary>
/// TCP traffic timings counters table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TcpTrafficTimingsTableSection" /> class.
/// </remarks>
/// <param name="tcpConnectionTimingsAnalysis">TCP connection timings analysis.</param>
public class TcpTrafficTimingsTableSection(TcpConnectionTimingsAnalysis tcpConnectionTimingsAnalysis) : TableSection
{
    private const string LatencyNotAvailable = "_";
    private readonly TcpConnectionTimingsAnalysis _tcpConnectionTimingsAnalysis = tcpConnectionTimingsAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionTimingsAnalysis));

    public TcpTrafficTimingsTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionTimingsAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "TCP Traffic Timings";

    /// <inheritdoc />
    protected override string TableHeaderDescription => "The percentiles of time for connection operations.";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - not enough packets to calculate traffic timings were captured.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Timing",
            "50th %",
            "90th %",
            "95th %",
            "99th %",
        ];

    /// <inheritdoc />
    protected override List<string[]>? GetTableData()
    {
        if (_tcpConnectionTimingsAnalysis.ConnectionDurations.IsEmpty &&
            _tcpConnectionTimingsAnalysis.HandshakeDurations.IsEmpty &&
            _tcpConnectionTimingsAnalysis.ResetAndNextSynDurations.IsEmpty)
        {
            return null;
        }

        var rows = new List<string[]>
        {
            new[]
            {
                "Connection Duration",
                _tcpConnectionTimingsAnalysis.ConnectionDurations.GetTimestampForPercentile(50) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ConnectionDurations.GetTimestampForPercentile(90) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ConnectionDurations.GetTimestampForPercentile(95) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ConnectionDurations.GetTimestampForPercentile(99) ?? LatencyNotAvailable,
            },
            new[]
            {
                "Handshake Duration",
                _tcpConnectionTimingsAnalysis.HandshakeDurations.GetTimestampForPercentile(50) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.HandshakeDurations.GetTimestampForPercentile(90) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.HandshakeDurations.GetTimestampForPercentile(95) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.HandshakeDurations.GetTimestampForPercentile(99) ?? LatencyNotAvailable,
            },
            new[]
            {
                "Between RST and SYN",
                _tcpConnectionTimingsAnalysis.ResetAndNextSynDurations.GetTimestampForPercentile(50) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ResetAndNextSynDurations.GetTimestampForPercentile(90) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ResetAndNextSynDurations.GetTimestampForPercentile(95) ?? LatencyNotAvailable,
                _tcpConnectionTimingsAnalysis.ResetAndNextSynDurations.GetTimestampForPercentile(99) ?? LatencyNotAvailable,
            },
        };

        return rows;
    }
}
