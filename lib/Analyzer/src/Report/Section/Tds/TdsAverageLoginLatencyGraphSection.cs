// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using System;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// Tcp Packet Reset Graph Section which graphs the Tcp resets over time.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsAverageLoginLatencyGraphSection" /> class.
/// </remarks>
/// <param name="tdsConnectionLatencyAnalysis">TDS connection latency analysis.</param>
/// <exception cref="ArgumentNullException">Thrown if <paramref name="tdsConnectionLatencyAnalysis" /> is null.</exception>
public class TdsAverageLoginLatencyGraphSection(TdsConnectionLatencyAnalysis tdsConnectionLatencyAnalysis) : DateTimeGraphSection
{
    private readonly TdsConnectionLatencyAnalysis _tdsConnectionLatencyAnalysis = tdsConnectionLatencyAnalysis ?? throw new ArgumentNullException(nameof(tdsConnectionLatencyAnalysis));

    public TdsAverageLoginLatencyGraphSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredApplicationLayerConnectionAnalysis<TdsConnectionLatencyAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string NoDataMessage => $"{GraphHeaderTitle} graph cannot be created - captured packets didn't contain any TDS latencies.";

    /// <inheritdoc />
    protected override string GraphHeaderTitle => "TDS Average Connection Latency";

    /// <inheritdoc />
    protected override string GraphHeaderDescription => "Graph showing TDS average connection latency in milliseconds over the period of the packet capture operation.";

    /// <inheritdoc />
    protected override string GraphXAxisLabel => "TIME PERIOD OF DAY (HH:MM:SS)";

    /// <inheritdoc />
    protected override string GraphYAxisLabel => "LATENCY ms";

    /// <inheritdoc />
    protected override string GraphXAxisDateTimeFormat => "HH:mm:ss";

    /// <inheritdoc />
    protected override long[] GetXAxisData()
    {
        return [.. _tdsConnectionLatencyAnalysis.TdsConnectionLatencies.Keys.Select(x => x.Ticks)];
    }

    /// <inheritdoc />
    protected override long[] GetYAxisData()
    {
        return [.. _tdsConnectionLatencyAnalysis.TdsConnectionLatencies.Values.Select(x => (long)x.TotalMilliseconds)];
    }
}
