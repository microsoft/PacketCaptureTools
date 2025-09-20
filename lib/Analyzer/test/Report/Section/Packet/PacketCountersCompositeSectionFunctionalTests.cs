// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class PacketCountersCompositeSectionFunctionalTests
{
    private readonly PacketCountersCompositeSection _sut;

    private readonly TextRenderer _textRenderer;
    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;

    private readonly PacketCounterAnalysis _packetCounterAnalysis;
    private readonly ThroughputAnalysis _throughputAnalysis;
    private readonly TcpPacketResetAnalysis _tcpPacketResetAnalysis;
    private readonly TcpPercentageOfDataControlAnalysis _tcpPercentageOfDataControlAnalysis;
    private readonly TcpConnectionCounterAnalysis _tcpConnectionCounterAnalysis;
    private readonly TcpConnectionRetransmissionAnalysis _tcpConnectionRetransmissionAnalysis;
    private readonly TcpConnectionTimingsAnalysis _tcpConnectionTimingsAnalysis;

    private readonly IPacketAnalysis[] _packetAnalyses;
    private readonly ITransportLayerConnectionAnalysis[] _transportLayerConnectionAnalyses;

    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.168.0.1");
    private static readonly IEnumerable<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> { _referenceIpAddress };

    private readonly IPacketFlowDetector _packetFlowDetector;

    public PacketCountersCompositeSectionFunctionalTests()
    {
        _textRenderer = new TextRenderer();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();

        _packetCounterAnalysis = AnalysisFixtureFactory.GetPacketCounterAnalysis(_packetFlowDetector);
        _throughputAnalysis = AnalysisFixtureFactory.GetThroughputAnalysis();
        _tcpPacketResetAnalysis = AnalysisFixtureFactory.GetTcpPacketResetAnalysis(_packetFlowDetector);
        _tcpPercentageOfDataControlAnalysis = AnalysisFixtureFactory.GetTcpPercentageOfDataControlAnalysis(_packetFlowDetector);
        _tcpConnectionCounterAnalysis = AnalysisFixtureFactory.GetTcpConnectionCounterAnalysis();
        _tcpConnectionRetransmissionAnalysis = AnalysisFixtureFactory.GetTcpConnectionRetransmissionAnalysis();
        _tcpConnectionTimingsAnalysis = AnalysisFixtureFactory.GetTcpConnectionTimingsAnalysis();

        _packetAnalyses =
        [
            _packetCounterAnalysis,
            _throughputAnalysis,
            _tcpPacketResetAnalysis,
            _tcpPercentageOfDataControlAnalysis,
        ];

        _transportLayerConnectionAnalyses =
        [
            _tcpConnectionCounterAnalysis,
            _tcpConnectionRetransmissionAnalysis,
            _tcpConnectionTimingsAnalysis,
        ];

        var analysisContainer = new AnalysisContainer();
        analysisContainer.AddPacketAnalysis(_packetCounterAnalysis);
        analysisContainer.AddPacketAnalysis(_throughputAnalysis);
        analysisContainer.AddPacketAnalysis(_tcpPacketResetAnalysis);
        analysisContainer.AddPacketAnalysis(_tcpPercentageOfDataControlAnalysis);
        analysisContainer.AddTransportLayerConnectionAnalysis(_tcpConnectionCounterAnalysis);
        analysisContainer.AddTransportLayerConnectionAnalysis(_tcpConnectionRetransmissionAnalysis);
        analysisContainer.AddTransportLayerConnectionAnalysis(_tcpConnectionTimingsAnalysis);

        _sut = new PacketCountersCompositeSection(analysisContainer);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessages()
    {
        // Arrange
        var expectedResult =
            @"Packet Counters
---------------

Global Packet Counters table cannot be created - no packets were captured.

[Packet Counters per protocol]
The percent and count of packets received / sent for each protocol.

Network Layer table cannot be created - no network layer packets were captured.

Transport Layer table cannot be created - no transport layer packets were captured.

Throughput table cannot be created - not enough packets to calculate throughput were captured.

Per IP Packet Counters table cannot be created - no packets per IP address were captured.

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void Render_TextRenderer_RendersPacketCountersCompositeSection()
    {
        // Arrange
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        var transportLayerConnection = new TransportLayerConnection(
            sourceIpAddress: _referenceIpAddress,
            destinationIpAddress: IPAddress.Parse("192.168.1.1"),
            sourcePort: 1,
            destinationPort: 1);

        ProcessPacket(
            transportLayerConnection: transportLayerConnection,
            packetDirection: PacketDirection.Outgoing,
            capturedDateTime: DateTime.UtcNow,
            tcpPayloadSize: 100,
            originalPacketLength: 1000,
            tcpConnectionState: TcpConnectionState.SynSent);

        ProcessPacket(
            transportLayerConnection: transportLayerConnection,
            packetDirection: PacketDirection.Incoming,
            capturedDateTime: DateTime.UtcNow.AddHours(1),
            tcpPayloadSize: 1000,
            originalPacketLength: 3000,
            tcpConnectionState: TcpConnectionState.Established);

        ProcessPacket(
            transportLayerConnection: transportLayerConnection,
            packetDirection: PacketDirection.Incoming,
            capturedDateTime: DateTime.UtcNow.AddHours(2),
            tcpPayloadSize: 200,
            originalPacketLength: 2000,
            tcpConnectionState: TcpConnectionState.Closed);

        var expectedResult =
            @"Packet Counters
---------------

[Global Packet Counters]
A Total breakdown of all captured packets metrics.

+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| Total Packets | TCP Packets | TDS Packets | Resets | Retransmits | TCP Connections | TCP Sent | TCP Received | TCP Control % | TCP Data % |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| 3             | 3           | 3           | 0      | 0           | 1               | 100 B    | 1.172 KB     | 0.00 %        | 100.00 %   |
+---------------+-------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+

[Packet Counters per protocol]
The percent and count of packets received / sent for each protocol.

[Network Layer]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| IPv4     | 3     | 100.00 %   | 2        | 1    |
| IPv6     | 0     | 0.00 %     | 0        | 0    |
| ARP      | 0     | 0.00 %     | 0        | 0    |
+----------+-------+------------+----------+------+

[Transport Layer]

+----------+-------+------------+----------+------+
| Protocol | Count | Percentage | Received | Sent |
+----------+-------+------------+----------+------+
| TCP      | 3     | 100.00 %   | 2        | 1    |
| UDP      | 0     | 0.00 %     | 0        | 0    |
+----------+-------+------------+----------+------+

[Throughput]
The average, minimum and maximum number of packets and data transferred per second.

+-------------------+-----------+-------+-----------+
| Value             | Average   | Min   | Max       |
+-------------------+-----------+-------+-----------+
| Number of Packets | 0 /s      | 0 /s  | 1 /s      |
| Speed             | 0.833 B/s | 0 B/s | 2.93 KB/s |
+-------------------+-----------+-------+-----------+

[Per IP Packet Counters]
A Total breakdown of all captured packets metrics by IP address.

+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| Dst IP      | Total Packets | TCP Packets | TDS Packets | Resets (src, dst) | Retransmits | TCP Connections (New, Existing, Closed) | Average RTT(s) |
+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| 192.168.1.1 | 3             | 3           | 3           | (0, 0)            | 0           | (1, 1, 1)                               | 0.000          |
+-------------+---------------+-------------+-------------+-------------------+-------------+-----------------------------------------+----------------+

";

        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private void ProcessPacket(
        TransportLayerConnection transportLayerConnection,
        PacketDirection packetDirection,
        DateTime capturedDateTime,
        int originalPacketLength,
        uint tcpPayloadSize,
        TcpConnectionState tcpConnectionState)
    {
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: packetDirection == PacketDirection.Outgoing
                ? transportLayerConnection.SourcePort
                : transportLayerConnection.DestinationPort,
            destinationPort: packetDirection == PacketDirection.Outgoing
                ? transportLayerConnection.DestinationPort
                : transportLayerConnection.SourcePort,
            payloadSize: tcpPayloadSize);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: packetDirection == PacketDirection.Outgoing
                ? transportLayerConnection.SourceIpAddress
                : transportLayerConnection.DestinationIpAddress,
            destinationIpAddress: packetDirection == PacketDirection.Outgoing
                ? transportLayerConnection.DestinationIpAddress
                : transportLayerConnection.SourceIpAddress);

        var ethernetFrameFixture = _packetFixtureFactory.CreateEthernetFrameFixture(iPv4Packet);

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: ethernetFrameFixture,
            networkPacket: iPv4Packet,
            transportSegment: tcpSegment,
            capturedDateTime: capturedDateTime,
            originalPacketLength: originalPacketLength);

        var tcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection,
            tcpConnectionState: tcpConnectionState,
            packetFlowDetector: _packetFlowDetector);

        ProcessPacketAndSnapshot(capturedPacket, tcpConnectionSnapshot);
    }

    private void ProcessPacketAndSnapshot(CapturedPacket capturedPacket, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        foreach (var packetAnalysis in _packetAnalyses)
        {
            packetAnalysis.Process(capturedPacket);
        }

        foreach (var transportLayerConnectionAnalysis in _transportLayerConnectionAnalyses)
        {
            transportLayerConnectionAnalysis.Process(capturedPacket, tcpConnectionSnapshot);
        }
    }
}