// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Extensions.Size;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Global packet counters table section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="GlobalPacketCountersTableSection" /> class.
/// </remarks>
/// <param name="packetCounterAnalysis">Packet counter analysis.</param>
/// <param name="tcpConnectionRetransmissionAnalysis">TCP connection retransmission analysis.</param>
/// <param name="tcpConnectionCounterAnalysis">TCP connection counter analysis.</param>
/// <param name="tcpPacketResetAnalysis">TCP packet reset analysis.</param>
/// <param name="tcpPercentageOfDataControlAnalysis">TCP percentage of data control analysis.</param>
public class GlobalPacketCountersTableSection(
    PacketCounterAnalysis packetCounterAnalysis,
    TcpConnectionRetransmissionAnalysis tcpConnectionRetransmissionAnalysis,
    TcpConnectionCounterAnalysis tcpConnectionCounterAnalysis,
    TcpPacketResetAnalysis tcpPacketResetAnalysis,
    TcpPercentageOfDataControlAnalysis tcpPercentageOfDataControlAnalysis) : TableSection
{
    private readonly PacketCounterAnalysis _packetCounterAnalysis = packetCounterAnalysis ?? throw new ArgumentNullException(nameof(packetCounterAnalysis));
    private readonly TcpConnectionRetransmissionAnalysis _tcpConnectionRetransmissionAnalysis = tcpConnectionRetransmissionAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionRetransmissionAnalysis));
    private readonly TcpConnectionCounterAnalysis _tcpConnectionCounterAnalysis = tcpConnectionCounterAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionCounterAnalysis));
    private readonly TcpPacketResetAnalysis _tcpPacketResetAnalysis = tcpPacketResetAnalysis ?? throw new ArgumentNullException(nameof(tcpPacketResetAnalysis));
    private readonly TcpPercentageOfDataControlAnalysis _tcpPercentageOfDataControlAnalysis = tcpPercentageOfDataControlAnalysis ?? throw new ArgumentNullException(nameof(tcpPercentageOfDataControlAnalysis));

    public GlobalPacketCountersTableSection(IAnalysisProvider analysisProvider)
        : this(
              analysisProvider.GetRequiredPacketAnalysis<PacketCounterAnalysis>(),
              analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionRetransmissionAnalysis>(),
              analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionCounterAnalysis>(),
              analysisProvider.GetRequiredPacketAnalysis<TcpPacketResetAnalysis>(),
              analysisProvider.GetRequiredPacketAnalysis<TcpPercentageOfDataControlAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string TableHeaderTitle => "Global Packet Counters";

    /// <inheritdoc />
    protected override string TableHeaderDescription => "A Total breakdown of all captured packets metrics.";

    /// <inheritdoc />
    protected override string NoDataMessage => $"{TableHeaderTitle} table cannot be created - no packets were captured.";

    /// <inheritdoc />
    protected override string[] TableHeaders =>
        [
            "Total Packets",
            "TCP Packets",
            "TDS Packets",
            "Resets",
            "Retransmits",
            "TCP Connections",
            "TCP Sent",
            "TCP Received",
            "TCP Control %",
            "TCP Data %",
        ];

    /// <inheritdoc />
    protected override List<string[]>? GetTableData()
    {
        if (_packetCounterAnalysis.GlobalPacketCount == 0)
        {
            return null;
        }

        var totalTcpPackets = _packetCounterAnalysis.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP] +
                              _packetCounterAnalysis.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP];

        var totalTcpRetransmits = _tcpConnectionRetransmissionAnalysis.RetransmissionsByIpAddress.Sum(item => item.Value);
        var totalTcpConnections = _tcpConnectionCounterAnalysis.TcpConnectionMetrics.Values.Sum(m => m.UniqueConnectionCount);

        var rows = new List<string[]>
        {
            new[]
            {
                $"{_packetCounterAnalysis.GlobalPacketCount}",
                $"{totalTcpPackets}",
                $"{_packetCounterAnalysis.OutgoingTdsPacketCount + _packetCounterAnalysis.IncomingTdsPacketCount}",
                $"{_tcpPacketResetAnalysis.GlobalCount}",
                $"{totalTcpRetransmits}",
                $"{totalTcpConnections}",
                _tcpPercentageOfDataControlAnalysis.OutgoingTcpBytes.GetHumanReadableSize("###"),
                _tcpPercentageOfDataControlAnalysis.IncomingTcpBytes.GetHumanReadableSize("###"),
                $"{_tcpPercentageOfDataControlAnalysis.PercentageOfTcpControl:p}",
                $"{_tcpPercentageOfDataControlAnalysis.PercentageOfTcpData:p}",
            },
        };

        return rows;
    }
}
