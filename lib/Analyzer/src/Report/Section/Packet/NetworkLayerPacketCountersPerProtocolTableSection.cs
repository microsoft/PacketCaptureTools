// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Network layer packet counters per protocol table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="NetworkLayerPacketCountersPerProtocolTableSection" /> class.
/// </remarks>
/// <param name="packetCounterAnalysis">Packet counter analysis.</param>
public class NetworkLayerPacketCountersPerProtocolTableSection(
    PacketCounterAnalysis packetCounterAnalysis) : TableSection
{
    private readonly PacketCounterAnalysis _packetCounterAnalysis = packetCounterAnalysis ?? throw new ArgumentNullException($"{nameof(packetCounterAnalysis)}");

    public NetworkLayerPacketCountersPerProtocolTableSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredPacketAnalysis<PacketCounterAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "Network Layer";

    /// <inheritdoc />
    protected override string? TableHeaderDescription => null;

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - no network layer packets were captured.";

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
        long totalNetworkLayerPacketCount = _packetCounterAnalysis.IncomingCountByNetworkPacketProtocol.Sum(x => x.Value) +
                                            _packetCounterAnalysis.OutgoingCountByNetworkPacketProtocol.Sum(x => x.Value);

        if (totalNetworkLayerPacketCount == 0)
        {
            return null;
        }

        var rows = new List<string[]>();

        foreach (var networkPacketProtocol in _packetCounterAnalysis.OutgoingCountByNetworkPacketProtocol.Keys)
        {
            var tempRow = new List<string> { networkPacketProtocol.ToString() };
            long totalPacketCountPerProtocol = _packetCounterAnalysis.OutgoingCountByNetworkPacketProtocol[networkPacketProtocol] +
                                               _packetCounterAnalysis.IncomingCountByNetworkPacketProtocol[networkPacketProtocol];
            tempRow.Add(totalPacketCountPerProtocol.ToString());
            tempRow.Add(((double)totalPacketCountPerProtocol / totalNetworkLayerPacketCount).ToString("p"));
            tempRow.Add(_packetCounterAnalysis.IncomingCountByNetworkPacketProtocol[networkPacketProtocol].ToString());
            tempRow.Add(_packetCounterAnalysis.OutgoingCountByNetworkPacketProtocol[networkPacketProtocol].ToString());
            rows.Add([.. tempRow]);
        }

        return rows;
    }
}
