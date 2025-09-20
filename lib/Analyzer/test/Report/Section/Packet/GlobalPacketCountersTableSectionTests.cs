// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class GlobalPacketCountersTableSectionTests
{
    private const string HeaderTitle = "Global Packet Counters";
    private const string HeaderDescription = "A Total breakdown of all captured packets metrics.";
    private const string NoDataMessage = "Global Packet Counters table cannot be created - no packets were captured.";
    private readonly TextRenderer _textRenderer;

    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.168.0.1");
    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { _referenceIpAddress };
    private readonly IPacketFlowDetector _packetFlowDetector;

    public GlobalPacketCountersTableSectionTests()
    {
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _textRenderer = new TextRenderer();
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
    }

    [Fact]
    public void Constructor_PacketCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "packetCounterAnalysis";

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(_packetFlowDetector);
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);

        // Act
        Func<GlobalPacketCountersTableSection> function = () => new GlobalPacketCountersTableSection(
            packetCounterAnalysis: null!,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }


    [Fact]
    public void Constructor_TcpConnectionRetransmissionAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpConnectionRetransmissionAnalysis";

        var packetCounterAnalysis = new PacketCounterAnalysis(_packetFlowDetector, new HashSet<int>(1));
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(_packetFlowDetector);
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);

        // Act
        Func<GlobalPacketCountersTableSection> function = () => new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: null!,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }


    [Fact]
    public void Constructor_TcpConnectionCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "packetCounterAnalysis";

        var packetCounterAnalysis = new PacketCounterAnalysis(_packetFlowDetector, new HashSet<int>(1));
        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(_packetFlowDetector);
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);

        // Act
        Func<GlobalPacketCountersTableSection> function = () => new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: null!,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }


    [Fact]
    public void Constructor_TcpPacketResetAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpPacketResetAnalysis";

        var packetCounterAnalysis = new PacketCounterAnalysis(_packetFlowDetector, new HashSet<int>(1));
        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);

        // Act
        Func<GlobalPacketCountersTableSection> function = () => new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: null!,
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }


    [Fact]
    public void Constructor_TcpPercentageOfDataControlAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpPercentageOfDataControlAnalysis";

        var packetCounterAnalysis = new PacketCounterAnalysis(_packetFlowDetector, new HashSet<int>(1));
        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis();
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis();
        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(_packetFlowDetector);

        // Act
        Func<GlobalPacketCountersTableSection> function = () => new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis: null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }


    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
    {
        // Arrange
        var sut = GetTable();

        var expectedResult =
            $@"{NoDataMessage}

";

        // Act
        sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void Render_TextRenderer_RendersGlobalPacketCountersTableSectionWithData()
    {
        var sut = GetTable(
            totalPackets: 1000,
            tcpPackets: 600,
            tdsPackets: 400,
            resets: 100,
            retransmits: 200,
            tcpConnections: 100,
            tcpSend: 400,
            tcpReceived: 200,
            tcpControlPercentage: 0.60);

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| Total Packets | TCP Packets | TDS Packets | Resets | Retransmits | TCP Connections | TCP Sent | TCP Received | TCP Control % | TCP Data % |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| 1000          | 600         | 400         | 100    | 200         | 100             | 400 B    | 200 B        | 60.00 %       | 40.00 %    |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+

";

        // Act
        sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private GlobalPacketCountersTableSection GetTable(
        int totalPackets = 0,
        int tcpPackets = 0,
        int tdsPackets = 0,
        int resets = 0,
        int retransmits = 0,
        int tcpConnections = 0,
        ulong tcpSend = 0,
        ulong tcpReceived = 0,
        double tcpControlPercentage = 0)
    {
        var outgoingCountByTransportSegmentProtocol = new Dictionary<TransportSegmentProtocol, int>
        {
            { TransportSegmentProtocol.TCP, tcpPackets },
        };

        var incomingCountByTransportPacketProtocol = new Dictionary<TransportSegmentProtocol, int>
        {
            { TransportSegmentProtocol.TCP, 0 },
        };

        var retransmissionsByIpAddress = new Dictionary<IPAddress, int>
        {
            { IPAddress.Any, retransmits },
        };

        var ipAggregatedMetrics = new Dictionary<IPAddress, TcpConnectionCounterMetrics>
        {
            { IPAddress.Any, new TcpConnectionCounterMetrics(uniqueConnectionCount: tcpConnections) },
        };

        var tcpConnectionMetrics = new Dictionary<TransportLayerConnection, TcpConnectionCounterMetrics>
        {
            { new TransportLayerConnection(IPAddress.Any, IPAddress.Any, 0, 0), new TcpConnectionCounterMetrics(uniqueConnectionCount: tcpConnections) },
        };

        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            globalPacketCount: totalPackets,
            outgoingTdsPacketCount: tdsPackets,
            incomingTdsPacketCount: 0,
            outgoingCountByTransportSegmentProtocol: outgoingCountByTransportSegmentProtocol,
            incomingCountByTransportSegmentProtocol: incomingCountByTransportPacketProtocol);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            globalCount: resets);

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(retransmissionsByIpAddress);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis(
            initialIpAggregatedMetrics: ipAggregatedMetrics,
            initialTcpConnectionMetrics: tcpConnectionMetrics);

        var totalTcpBytesPassed = tcpSend + tcpReceived;
        var totalTcpControlTrafficBytesPassed = (ulong)(tcpControlPercentage * totalTcpBytesPassed);
        var totalTcpDataTrafficBytesPassed = totalTcpBytesPassed - totalTcpControlTrafficBytesPassed;

        var tcpPercentageOfDataControlAnalysis = new TcpPercentageOfDataControlAnalysis(
            packetFlowDetector: _packetFlowDetector,
            outgoingTcpBytes: tcpSend,
            incomingTcpBytes: tcpReceived,
            totalTcpControlTrafficBytesPassed: totalTcpControlTrafficBytesPassed,
            totalTcpDataTrafficBytesPassed: totalTcpDataTrafficBytesPassed);

        return new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis);
    }
}