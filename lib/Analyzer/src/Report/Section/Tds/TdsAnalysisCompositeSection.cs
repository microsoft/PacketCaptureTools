// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

/// <summary>
/// TDS failed logins over time represented as a graph.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsAnalysisCompositeSection" /> class.
/// </remarks>
/// <param name="tdsFailedLoginConnectionTableSection">The table section that displays failed TDS login connection attempts.</param>
/// <param name="tdsLoginConnectionAnalysesTableSection">The table section that provides analyses of TDS login connections.</param>
/// <param name="tdsFailedConnectionLatencyTableSection">The table section that presents latency data for failed TDS connections.</param>
/// <param name="tdsAverageLoginLatencyGraphSection">The graph section that visualizes average login latency for TDS connections.</param>
/// <param name="tdsFailedLoginGraphSection">The graph section that displays failed TDS login attempts over time.</param>
public class TdsAnalysisCompositeSection(
    TdsFailedLoginConnectionTableSection tdsFailedLoginConnectionTableSection,
    TdsLoginConnectionAnalysesTableSection tdsLoginConnectionAnalysesTableSection,
    TdsFailedConnectionLatencyTableSection tdsFailedConnectionLatencyTableSection,
    TdsAverageLoginLatencyGraphSection tdsAverageLoginLatencyGraphSection,
    TdsFailedLoginGraphSection tdsFailedLoginGraphSection
        ) : CompositeSection
{
    public TdsAnalysisCompositeSection(IAnalysisProvider analysisProvider)
        : this(
              new TdsFailedLoginConnectionTableSection(analysisProvider),
              new TdsLoginConnectionAnalysesTableSection(analysisProvider),
              new TdsFailedConnectionLatencyTableSection(analysisProvider),
              new TdsAverageLoginLatencyGraphSection(analysisProvider),
              new TdsFailedLoginGraphSection(analysisProvider)
              )
    {
    }

    /// <inheritdoc />
    public override IEnumerable<ISection> Subsections { get; } = [
            tdsFailedLoginConnectionTableSection,
            tdsLoginConnectionAnalysesTableSection,
            tdsFailedConnectionLatencyTableSection,
            tdsAverageLoginLatencyGraphSection,
            tdsFailedLoginGraphSection
        ];

    /// <inheritdoc />
    protected override string SectionTitle => "TDS Analysis Report";
}
