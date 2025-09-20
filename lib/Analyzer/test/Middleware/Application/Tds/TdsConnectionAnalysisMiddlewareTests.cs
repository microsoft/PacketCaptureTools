// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Application.Tds;

public class TdsConnectionAnalysisMiddlewareTests
{
    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly HashSet<int> _tdsPort = new HashSet<int> { 1433 };
    private readonly TdsConnectionAnalysisMiddleware _sut;

    public TdsConnectionAnalysisMiddlewareTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new TdsConnectionAnalysisMiddleware(_packetFlowDetector, _tdsPort);
    }

    [Fact]
    public void Process_InvalidParameters_ReturnsNull()
    {
        // Arrange
        // Act
        var result = _sut.Process(null!, null!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Process_OutGoingPacket_TdsConnectionSnapshotWithPreLoginState()
    {
        // Arrange
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags(psh: true, syn: true, ack: true));

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            destinationIpAddress: _referenceIpAddress,
            sourceIpAddress: _ipv4Address);

        var transportConnection = new TransportLayerConnection(
            sourceIpAddress: ipPacket.SourceAddress,
            destinationIpAddress: ipPacket.DestinationAddress,
            sourcePort: tcpSegment.SourcePort,
            destinationPort: tcpSegment.DestinationPort);

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            networkPacket: ipPacket,
            transportSegment: tcpSegment);

        var tcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportConnection,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.Established);

        // Act
        var tdsConnectionSnapshot = _sut.Process(capturedPacket, tcpConnectionSnapshot) as TdsConnectionSnapshot;

        // Assert
        tdsConnectionSnapshot.Should().NotBeNull();
        tdsConnectionSnapshot.State.TdsConnectionState.Should().Be(TdsConnectionState.PreLogin);
    }
}