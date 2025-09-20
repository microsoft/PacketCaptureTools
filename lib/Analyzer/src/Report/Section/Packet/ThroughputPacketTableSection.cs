// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Extensions.Size;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Traffic timings counters table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ThroughputPacketTableSection" /> class.
/// </remarks>
/// <param name="throughputAnalysis">Throughput analysis.</param>
public class ThroughputPacketTableSection(ThroughputAnalysis throughputAnalysis) : TableSection
{
    private readonly ThroughputAnalysis _throughputAnalysis = throughputAnalysis ?? throw new ArgumentNullException(nameof(throughputAnalysis));

    public ThroughputPacketTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredPacketAnalysis<ThroughputAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "Throughput";

    /// <inheritdoc />
    protected override string TableHeaderDescription => "The average, minimum and maximum number of packets and data transferred per second.";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - not enough packets to calculate throughput were captured.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Value",
            "Average",
            "Min",
            "Max",
        ];

    /// <inheritdoc />
    protected override List<string[]>? GetTableData()
    {
        if (_throughputAnalysis.AverageNumberOfPackets == 0 &&
            _throughputAnalysis.MinNumberOfPackets == 0 &&
            _throughputAnalysis.MaxNumberOfPackets == 0 &&
            _throughputAnalysis.AverageSpeedOfDataTransfer == 0 &&
            _throughputAnalysis.MinSpeedOfDataTransfer == 0 &&
            _throughputAnalysis.MaxSpeedOfDataTransfer == 0)
        {
            return null;
        }

        var rows = new List<string[]>
        {
            new[]
            {
                "Number of Packets", $"{_throughputAnalysis.AverageNumberOfPackets:0.###} /s",
                $"{_throughputAnalysis.MinNumberOfPackets:0.###} /s",
                $"{_throughputAnalysis.MaxNumberOfPackets:0.###} /s",
            },
            new[]
            {
                "Speed", $"{_throughputAnalysis.AverageSpeedOfDataTransfer.GetHumanReadableSize("###")}/s",
                $"{_throughputAnalysis.MinSpeedOfDataTransfer.GetHumanReadableSize("###")}/s",
                $"{_throughputAnalysis.MaxSpeedOfDataTransfer.GetHumanReadableSize("###")}/s",
            },
        };

        return rows;
    }
}
