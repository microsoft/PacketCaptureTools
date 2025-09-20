// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Per IP packet counters table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="PerIpPacketCountersTableSection" /> class.
/// </remarks>
/// <param name="packetCounterAnalysis">Packet counter analysis.</param>
/// <param name="tcpConnectionRetransmissionAnalysis">TCP connection retransmission analysis.</param>
/// <param name="tcpConnectionCounterAnalysis">TCP connection counter analysis.</param>
/// <param name="tcpPacketResetAnalysis">TCP packet reset analysis.</param>
public class PerIpPacketCountersTableSection(
    PacketCounterAnalysis packetCounterAnalysis,
    TcpConnectionRetransmissionAnalysis tcpConnectionRetransmissionAnalysis,
    TcpConnectionCounterAnalysis tcpConnectionCounterAnalysis,
    TcpPacketResetAnalysis tcpPacketResetAnalysis) : TableSection
{
    private readonly PacketCounterAnalysis _packetCounterAnalysis = packetCounterAnalysis ?? throw new ArgumentNullException(nameof(packetCounterAnalysis));
    private readonly TcpConnectionRetransmissionAnalysis _tcpConnectionRetransmissionAnalysis = tcpConnectionRetransmissionAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionRetransmissionAnalysis));
    private readonly TcpConnectionCounterAnalysis _tcpConnectionCounterAnalysis = tcpConnectionCounterAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionCounterAnalysis));
    private readonly TcpPacketResetAnalysis _tcpPacketResetAnalysis = tcpPacketResetAnalysis ?? throw new ArgumentNullException(nameof(tcpPacketResetAnalysis));

    public PerIpPacketCountersTableSection(IAnalysisProvider analysisProvider)
        : this(
              analysisProvider.GetRequiredPacketAnalysis<PacketCounterAnalysis>(),
              analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionRetransmissionAnalysis>(),
              analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionCounterAnalysis>(),
              analysisProvider.GetRequiredPacketAnalysis<TcpPacketResetAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "Per IP Packet Counters";

    /// <inheritdoc />
    protected override string TableHeaderDescription => "A Total breakdown of all captured packets metrics by IP address.";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - no packets per IP address were captured.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Dst IP",
            "Total Packets",
            "TCP Packets",
            "TDS Packets",
            "Resets (src, dst)",
            "Retransmits",
            "TCP Connections (New, Existing, Closed)",
            "Average RTT(s)",
        ];

    /// <inheritdoc />
    protected override List<string[]> GetTableData()
    {
        var rows = new List<string[]>();

        foreach (var iPCounterMetricsTuple in _packetCounterAnalysis.PerIpPacketCounters.OrderBy(c => c.Key.ToString()))
        {
            var tempRow = new List<string>
            {
                iPCounterMetricsTuple.Key.ToString(),
                iPCounterMetricsTuple.Value.TotalPacketCount.ToString(),
                iPCounterMetricsTuple.Value.TcpPacketCount.ToString(),
                iPCounterMetricsTuple.Value.TdsPacketCount.ToString(),
            };

            if (_tcpPacketResetAnalysis.PerIpResetCount.TryGetValue(iPCounterMetricsTuple.Key, out (int asSource, int asDestination) perIpResetCountValue))
            {
                var asSourceReset = perIpResetCountValue.asSource;
                var asDestinationReset = perIpResetCountValue.asDestination;
                tempRow.Add($"({asSourceReset}, {asDestinationReset})");
            }
            else
            {
                tempRow.Add("(0, 0)");
            }

            if (_tcpConnectionRetransmissionAnalysis.RetransmissionsByIpAddress.TryGetValue(iPCounterMetricsTuple.Key, out int retransmissionCountValue))
            {
                tempRow.Add(retransmissionCountValue.ToString());
            }
            else
            {
                tempRow.Add("0");
            }

            if (_tcpConnectionCounterAnalysis.IpAggregatedMetrics.TryGetValue(iPCounterMetricsTuple.Key, out TcpConnectionCounterMetrics? aggregatedMetrics))
            {
                tempRow.Add($"({aggregatedMetrics.UniqueConnectionCount}, {aggregatedMetrics.EstablishedConnectionCount}, {aggregatedMetrics.ClosedConnectionCount})");
                tempRow.Add(aggregatedMetrics.AverageRoundTripTime.ToString("N3"));
            }
            else
            {
                tempRow.Add("(0, 0, 0)");
                tempRow.Add("0.000");
            }

            rows.Add([.. tempRow]);
        }

        return rows;
    }
}
