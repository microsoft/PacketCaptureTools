// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// TDS failed logins over time represented as a graph.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsFailedLoginGraphSection" /> class.
/// </remarks>
/// <param name="tdsConnectionAnalysis">The TDS connection analysis results.</param>
/// <exception cref="ArgumentNullException">TDS connection analysis cannot be null.</exception>
public class TdsFailedLoginGraphSection(TdsLoginConnectionAnalysis tdsConnectionAnalysis) : GraphSection
{
    private readonly TdsLoginConnectionAnalysis _tdsConnectionAnalysis = tdsConnectionAnalysis ?? throw new ArgumentNullException(nameof(tdsConnectionAnalysis));

    private Dictionary<DateTime, int>? _failedConnectionStatesByTime;

    public TdsFailedLoginGraphSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredApplicationLayerConnectionAnalysis<TdsLoginConnectionAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string NoDataMessage => $"{GraphHeaderTitle} graph cannot be created - captured packets didn't contain any failed TDS logins.";

    /// <inheritdoc />
    protected override string GraphHeaderTitle => "TDS Login Failures";

    /// <inheritdoc />
    protected override string GraphHeaderDescription => "Graph with TDS connection failures over the period of the packet capture operation.";

    /// <inheritdoc />
    protected override string GraphXAxisLabel => "TIME PERIOD OF DAY (HH:MM:SS)";

    /// <inheritdoc />
    protected override string GraphYAxisLabel => "TDS FAILS";

    /// <inheritdoc />
    protected override Func<long, string> GraphXAxisValueFormatter =>
        x => new DateTime(x).ToString("HH:mm:ss");

    /// <inheritdoc />
    protected override Func<long, string> GraphYAxisValueFormatter =>
        x => x.ToString();

    private Dictionary<DateTime, int> FailedConnectionStatesByTime => _failedConnectionStatesByTime ??= _tdsConnectionAnalysis.GetNumberOfFailedTdsConnectionsByTime();

    /// <inheritdoc />
    protected override long[] GetXAxisData()
    {
        return [.. FailedConnectionStatesByTime.Keys.Select(x => x.Ticks)];
    }

    /// <inheritdoc />
    protected override long[] GetYAxisData()
    {
        return [.. FailedConnectionStatesByTime.Values.Select(x => (long)x)];
    }
}
