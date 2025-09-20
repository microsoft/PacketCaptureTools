// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class PerIpPacketCountersTableSectionTests
{
    private const string HeaderTitle = "Per IP Packet Counters";
    private const string HeaderDescription = "A Total breakdown of all captured packets metrics by IP address.";
    private const string NoDataMessage = "Per IP Packet Counters table cannot be created - no packets per IP address were captured.";
    private readonly PerIpPacketCountersTableSection _sut;

    private readonly TextRenderer _textRenderer;

    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.168.0.1");
    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { _referenceIpAddress };

    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly Dictionary<IPAddress, int> _retransmissionsByIpAddress;
    private readonly Dictionary<IPAddress, PerIpCounterMetrics> _perIpPacketCounters;
    private readonly Dictionary<IPAddress, TcpConnectionCounterMetrics> _tcpConnectionCounterMetrics;
    private readonly Dictionary<IPAddress, (int asSource, int asDestination)> _perIpResetCount;

    public PerIpPacketCountersTableSectionTests()
    {
        _textRenderer = new TextRenderer();

        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _retransmissionsByIpAddress = [];
        _perIpPacketCounters = [];
        _tcpConnectionCounterMetrics = [];
        _perIpResetCount = [];

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(_retransmissionsByIpAddress);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis(_tcpConnectionCounterMetrics);

        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            perIpPacketCounters: _perIpPacketCounters);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            perIpResetCount: _perIpResetCount);

        _sut = new PerIpPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis);
    }

    [Fact]
    public void Constructor_PacketCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "packetCounterAnalysis";

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(_retransmissionsByIpAddress);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis(_tcpConnectionCounterMetrics);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            perIpResetCount: _perIpResetCount);

        // Act
        Func<PerIpPacketCountersTableSection> function = () => new PerIpPacketCountersTableSection(
            packetCounterAnalysis: null!,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Constructor_TcpConnectionRetransmissionAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpConnectionRetransmissionAnalysis";


        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            perIpPacketCounters: _perIpPacketCounters);

        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis(_tcpConnectionCounterMetrics);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            perIpResetCount: _perIpResetCount);

        // Act
        Func<PerIpPacketCountersTableSection> function = () => new PerIpPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: null!,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Constructor_TcpConnectionCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpConnectionCounterAnalysis";


        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            perIpPacketCounters: _perIpPacketCounters);

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(_retransmissionsByIpAddress);

        var tcpPacketResetAnalysis = new TcpPacketResetAnalysis(
            packetFlowDetector: _packetFlowDetector,
            perIpResetCount: _perIpResetCount);

        // Act
        Func<PerIpPacketCountersTableSection> function = () => new PerIpPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: null!,
            tcpPacketResetAnalysis: tcpPacketResetAnalysis);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Constructor_TcpPacketResetAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "tcpPacketResetAnalysis";


        var packetCounterAnalysis = new PacketCounterAnalysis(
            packetFlowDetector: _packetFlowDetector,
            tdsPorts: new HashSet<int> { 1 },
            perIpPacketCounters: _perIpPacketCounters);

        var tcpConnectionRetransmissionAnalysis = new TcpConnectionRetransmissionAnalysis(_retransmissionsByIpAddress);
        var tcpConnectionCounterAnalysis = new TcpConnectionCounterAnalysis(_tcpConnectionCounterMetrics);

        // Act
        Func<PerIpPacketCountersTableSection> function = () => new PerIpPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis: null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
    {
        // Arrange
        var expectedResult =
            $@"{NoDataMessage}

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void Render_TextRenderer_RendersPerIpPacketCountersTableSection()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("168.63.129.16");

        AddTableRow(
            dstIp: ipAddress,
            totalPackets: int.MaxValue,
            tcpPackets: int.MaxValue,
            tdsPackets: int.MaxValue,
            resetsSrc: int.MaxValue,
            resetsDst: int.MaxValue,
            retransmits: int.MaxValue,
            tcpConnectionsNew: int.MaxValue,
            tcpConnectionsExisting: int.MaxValue,
            tcpConnectionsClosed: int.MaxValue,
            averageRtt: TimeSpan.FromMilliseconds(12345));

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

+---------------+---------------+-------------+-------------+--------------------------+-------------+-----------------------------------------+----------------+
| Dst IP        | Total Packets | TCP Packets | TDS Packets | Resets (src, dst)        | Retransmits | TCP Connections (New, Existing, Closed) | Average RTT(s) |
+---------------+---------------+-------------+-------------+--------------------------+-------------+-----------------------------------------+----------------+
| 168.63.129.16 | 2147483647    | 2147483647  | 2147483647  | (2147483647, 2147483647) | 2147483647  | (2147483647, 2147483647, 2147483647)    | 12.345         |
+---------------+---------------+-------------+-------------+--------------------------+-------------+-----------------------------------------+----------------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private void AddTableRow(
        IPAddress dstIp,
        int totalPackets = 0,
        int tcpPackets = 0,
        int tdsPackets = 0,
        int resetsSrc = 0,
        int resetsDst = 0,
        int retransmits = 0,
        int tcpConnectionsNew = 0,
        int tcpConnectionsExisting = 0,
        int tcpConnectionsClosed = 0,
        TimeSpan averageRtt = default)
    {
        _perIpPacketCounters.Add(
            key: dstIp,
            value: new PerIpCounterMetrics
            {
                TotalPacketCount = totalPackets,
                TcpPacketCount = tcpPackets,
                TdsPacketCount = tdsPackets,
            });

        _perIpResetCount.Add(
            key: dstIp,
            value: (resetsSrc, resetsDst)
        );

        _retransmissionsByIpAddress.Add(
            key: dstIp,
            value: retransmits);

        _tcpConnectionCounterMetrics.Add(
            key: dstIp,
            value: new TcpConnectionCounterMetrics(
                cumulativeRoundTripTime: averageRtt,
                countRoundTripTime: 1)
            {
                UniqueConnectionCount = tcpConnectionsNew,
                EstablishedConnectionCount = tcpConnectionsExisting,
                ClosedConnectionCount = tcpConnectionsClosed,
            });
    }
}