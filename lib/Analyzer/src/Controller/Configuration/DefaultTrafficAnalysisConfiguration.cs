// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using Microsoft.PacketCapture.Analyzer.Report.Section.Metadata;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Controller.Configuration;

/// <summary>
/// Default network traffic analysis configuration.
/// </summary>
public class DefaultTrafficAnalysisConfiguration : IAnalysisConfiguration
{
    private const string ReportVersion = "v1.0";

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTrafficAnalysisConfiguration" /> class.
    /// </summary>
    /// <param name="metadata">The packet capture metadata.</param>
    public DefaultTrafficAnalysisConfiguration(
        SessionMetadata metadata)
    {
        _ = metadata ?? throw new ArgumentNullException(nameof(metadata));

        ApplicationConnectionMiddlewares = [];
        ApplicationLayerAnalyses = [];

        var packetFlowDetector = new ReferenceIpPacketFlowDetector(metadata.CaptureAddresses);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(packetFlowDetector);
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(packetFlowDetector);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpConnectionTimingsAnalysis = new TcpConnectionTimingsAnalysis();
        var throughputAnalysis = new ThroughputAnalysis();
        var packetCounterAnalysis = new PacketCounterAnalysis(packetFlowDetector, new HashSet<int> { -1 });

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

        PacketAnalyses = analysisContainer.PacketAnalyses;
        TransportLayerAnalyses = analysisContainer.TransportLayerAnalyses;
        
        IEnumerable<ISection> sections = [
            new SessionMetadataSection(metadata, ReportVersion),
            new PacketCountersCompositeSection(analysisContainer),
            new TcpTrafficTimingsTableSection(tcpConnectionTimingsAnalysis),
            new TcpPacketResetGraphSection(analysisContainer),
            new TcpConnectionRetransmissionGraphSection(analysisContainer)
        ];

        Report = new BaseReport(sections);
    }

    public ILoggerFactory? LoggerFactory { get; }

    public IReport Report { get; }

    public IEnumerable<IPacketAnalysis> PacketAnalyses { get; }

    public IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses { get; }

    public IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses { get; }

    public IEnumerable<ITransportLayerConnectionMiddleware> TransportLayerConnectionMiddlewares { get; }

    public IEnumerable<IApplicationConnectionMiddleware> ApplicationConnectionMiddlewares { get; }
}
