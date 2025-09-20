// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Transport layer packet counters per protocol table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TransportLayerPacketCountersPerProtocolTableSection" /> class.
/// </remarks>
/// <param name="packetCounterAnalysis">Packet counter analysis.</param>
public class TransportLayerPacketCountersPerProtocolTableSection(PacketCounterAnalysis packetCounterAnalysis) : TableSection
{
    private readonly PacketCounterAnalysis _packetCounterAnalysis = packetCounterAnalysis ?? throw new ArgumentNullException(nameof(packetCounterAnalysis));

    public TransportLayerPacketCountersPerProtocolTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredPacketAnalysis<PacketCounterAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "Transport Layer";

    /// <inheritdoc />
    protected override string? TableHeaderDescription => null;

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - no transport layer packets were captured.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Protocol",
            "Count",
            "Percentage",
            "Received",
            "Sent",
        ];

    /// <inheritdoc />
    protected override List<string[]>? GetTableData()
    {
        long totalTransportLayerPacketCount = _packetCounterAnalysis.IncomingCountByTransportSegmentProtocol.Sum(x => x.Value) +
                                              _packetCounterAnalysis.OutgoingCountByTransportSegmentProtocol.Sum(x => x.Value);

        if (totalTransportLayerPacketCount == 0)
        {
            return null;
        }

        var rows = new List<string[]>();

        foreach (var transportSegmentProtocol in _packetCounterAnalysis.OutgoingCountByTransportSegmentProtocol.Keys)
        {
            var tempRow = new List<string> { transportSegmentProtocol.ToString() };
            long totalPacketCountPerProtocol = _packetCounterAnalysis.OutgoingCountByTransportSegmentProtocol[transportSegmentProtocol] +
                                               _packetCounterAnalysis.IncomingCountByTransportSegmentProtocol[transportSegmentProtocol];
            tempRow.Add(totalPacketCountPerProtocol.ToString());
            tempRow.Add(((double)totalPacketCountPerProtocol / totalTransportLayerPacketCount).ToString("p"));
            tempRow.Add(_packetCounterAnalysis.IncomingCountByTransportSegmentProtocol[transportSegmentProtocol].ToString());
            tempRow.Add(_packetCounterAnalysis.OutgoingCountByTransportSegmentProtocol[transportSegmentProtocol].ToString());
            rows.Add([.. tempRow]);
        }

        return rows;
    }
}
