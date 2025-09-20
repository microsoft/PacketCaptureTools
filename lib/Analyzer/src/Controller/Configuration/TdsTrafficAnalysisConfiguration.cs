// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using Microsoft.PacketCapture.Analyzer.Report.Section.Help;
using Microsoft.PacketCapture.Analyzer.Report.Section.Metadata;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Controller.Configuration;

/// <summary>
/// Tds and Tcp network traffic analysis configuration.
/// </summary>
public class TdsTrafficAnalysisConfiguration : IAnalysisConfiguration
{
    private const string ReportVersion = "v1.0";

    private static readonly ISet<int> DefaultTdsPorts = new HashSet<int> { 1433 };

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsTrafficAnalysisConfiguration" /> class.
    /// </summary>
    /// <param name="sessionMetadata">The capture session metadata.</param>
    /// <param name="helpText">Help text.</param>
    /// <param name="tdsPorts">Custom Tds ports to be used for analysis.</param>
    public TdsTrafficAnalysisConfiguration(
        SessionMetadata sessionMetadata,
        string helpText,
        ISet<int>? tdsPorts = default)
    {
        tdsPorts ??= DefaultTdsPorts;

        var packetFlowDetector = new ReferenceIpPacketFlowDetector(sessionMetadata.CaptureAddresses);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(packetFlowDetector);
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(packetFlowDetector);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpConnectionTimingsAnalysis = new TcpConnectionTimingsAnalysis();
        var throughputAnalysis = new ThroughputAnalysis();
        var tdsLoginConnectionAnalysis = new TdsLoginConnectionAnalysis();
        var tdsConnectionLatencyAnalysis = new TdsConnectionLatencyAnalysis();
        var packetCounterAnalysis = new PacketCounterAnalysis(packetFlowDetector, tdsPorts);

        ApplicationConnectionMiddlewares =
        [
            new TdsConnectionAnalysisMiddleware(packetFlowDetector, tdsPorts),
        ];

        TransportLayerConnectionMiddlewares =
        [
            new TcpConnectionAnalysisMiddleware(packetFlowDetector),
        ];

        AnalysisContainer analysisContainer = new();
        analysisContainer.AddPacketAnalysis(tcpPacketResetAnalysis);
        analysisContainer.AddPacketAnalysis(packetCounterAnalysis);
        analysisContainer.AddPacketAnalysis(throughputAnalysis);
        analysisContainer.AddPacketAnalysis(tcpPercentageOfDataControlAnalysis);

        analysisContainer.AddTransportLayerConnectionAnalysis(tcpConnectionCounterAnalysis);
        analysisContainer.AddTransportLayerConnectionAnalysis(tcpConnectionRetransmissionAnalysis);
        analysisContainer.AddTransportLayerConnectionAnalysis(tcpConnectionTimingsAnalysis);

        analysisContainer.AddApplicationLayerConnectionAnalysis(tdsLoginConnectionAnalysis);
        analysisContainer.AddApplicationLayerConnectionAnalysis(tdsConnectionLatencyAnalysis);

        PacketAnalyses = analysisContainer.PacketAnalyses;
        TransportLayerAnalyses = analysisContainer.TransportLayerAnalyses;
        ApplicationLayerAnalyses = analysisContainer.ApplicationLayerAnalyses;

        IEnumerable<ISection> sections = [
            new SessionMetadataSection(sessionMetadata, ReportVersion),
            new PacketCountersCompositeSection(analysisContainer),
            new TcpTrafficTimingsTableSection(tcpConnectionTimingsAnalysis),
            new TcpPacketResetGraphSection(analysisContainer),
            new TcpConnectionRetransmissionGraphSection(analysisContainer),
            new TdsAnalysisCompositeSection(analysisContainer),
            new HelpSection(helpText),
        ];

        Report = new BaseReport(sections);
    }

    public ILoggerFactory? LoggerFactory { get; }

    public IReport Report { get; }

    public IEnumerable<IPacketAnalysis> PacketAnalyses { get; internal init; }

    public IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses { get; }

    public IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses { get; }

    public IEnumerable<ITransportLayerConnectionMiddleware> TransportLayerConnectionMiddlewares { get; }

    public IEnumerable<IApplicationConnectionMiddleware> ApplicationConnectionMiddlewares { get; }
}
