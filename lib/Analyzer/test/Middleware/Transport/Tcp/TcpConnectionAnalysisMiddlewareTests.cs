// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using Moq;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp;

public class TcpConnectionAnalysisMiddlewareTests
{
    private const string SourceIpAddress = "192.168.0.1";
    private const int SourcePort = 1;

    private const string DestinationIpAddress = "192.168.0.2";
    private const int DestinationPort = 2;

    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse(SourceIpAddress);

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress,
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly TransportLayerConnection _transportLayerConnection;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TcpConnectionAnalysisMiddleware _sut;

    private readonly Mock<IDictionary<TransportLayerConnection, TcpConnectionSnapshot>> _tcpConnectionSnapshotsMock;

    public TcpConnectionAnalysisMiddlewareTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();

        _transportLayerConnection = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _tcpConnectionSnapshotsMock = new Mock<IDictionary<TransportLayerConnection, TcpConnectionSnapshot>>();

        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _sut = new TcpConnectionAnalysisMiddleware(
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionSnapshots: _tcpConnectionSnapshotsMock.Object);
    }

    [Fact]
    public void ClassConstructor_PacketFlowDetectorIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "packetFlowDetector";

        // Act
        Func<TcpConnectionAnalysisMiddleware> function = () => new TcpConnectionAnalysisMiddleware(
            packetFlowDetector: null!);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor2_PacketFlowDetectorIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "packetFlowDetector";

        // Act
        Func<TcpConnectionAnalysisMiddleware> function = () => new TcpConnectionAnalysisMiddleware(
            packetFlowDetector: null!,
            tcpConnectionSnapshots: _tcpConnectionSnapshotsMock.Object);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor2_TcpConnectionsSnapshotsIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "tcpConnectionSnapshots";

        // Act
        Func<TcpConnectionAnalysisMiddleware> function = () => new TcpConnectionAnalysisMiddleware(
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionSnapshots: null!);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ProcessPacket_PhysicalFrameIsNotEthernetFrame_ReturnNull()
    {
        // Arrange
        var physicalFrame = new PhysicalFrameMock();

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: physicalFrame);

        // Act
        var result = _sut.ProcessPacket(capturedPacket);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ProcessPacket_NetworkPacketIsNotIPPacket_ReturnNull()
    {
        // Arrange
        var physicalFrame = _packetFixtureFactory.CreateEthernetFrameFixture(new NetworkPacketMock());

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: physicalFrame);

        // Act
        var result = _sut.ProcessPacket(capturedPacket);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ProcessPacket_TransportSegmentIsNotTcpSegment_ReturnNull()
    {
        // Arrange
        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: new TransportSegmentMock(),
            sourceIpAddress: _transportLayerConnection.SourceIpAddress,
            destinationIpAddress: _transportLayerConnection.DestinationIpAddress);

        var physicalFrame = _packetFixtureFactory.CreateEthernetFrameFixture(iPv4Packet);

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: physicalFrame);

        // Act
        var result = _sut.ProcessPacket(capturedPacket);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ProcessPacket_NewConnection_AddToDictionary()
    {
        // Arrange
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: _transportLayerConnection.DestinationPort,
            destinationPort: _transportLayerConnection.SourcePort,
            sequenceNumber: 0,
            acknowledgementNumber: 1,
            tcpFlags: new TcpFlags(syn: true));

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.DestinationIpAddress,
            destinationIpAddress: _transportLayerConnection.SourceIpAddress);

        var physicalFrame = _packetFixtureFactory.CreateEthernetFrameFixture(iPv4Packet);

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: physicalFrame);

        var expectedTcpConnectionSnapshot = new TcpConnectionSnapshot(
            ipPacket: iPv4Packet,
            tcpSegment: tcpSegment,
            transportConnection: _transportLayerConnection,
            packetFlowDetector: _packetFlowDetector);

        // Act
        var result = _sut.ProcessPacket(capturedPacket);

        // Assert
        result.Should().BeEquivalentTo(expectedTcpConnectionSnapshot);

        _tcpConnectionSnapshotsMock.Verify(
            dict => dict.Add(_transportLayerConnection, It.IsAny<TcpConnectionSnapshot>()),
            Times.Once);

        _tcpConnectionSnapshotsMock.Verify(
            dict => dict[It.IsAny<TransportLayerConnection>()],
            Times.Never);
    }

    [Fact]
    public void ProcessPacket_ExistingConnection_UpdateTcpConnectionSnapshot()
    {
        // Arrange
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: _transportLayerConnection.SourcePort,
            destinationPort: _transportLayerConnection.DestinationPort,
            sequenceNumber: 0,
            acknowledgementNumber: 1);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.SourceIpAddress,
            destinationIpAddress: _transportLayerConnection.DestinationIpAddress);

        var physicalFrame = _packetFixtureFactory.CreateEthernetFrameFixture(iPv4Packet);

        var timestamp = DateTime.UtcNow;

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: physicalFrame,
            capturedDateTime: timestamp);

        var expectedTcpConnectionSnapshot = new Mock<TcpConnectionSnapshot>(
            MockBehavior.Default,
            iPv4Packet,
            tcpSegment,
            _transportLayerConnection,
            _packetFlowDetector,
            timestamp);

        _tcpConnectionSnapshotsMock
            .Setup(dict => dict.ContainsKey(_transportLayerConnection))
            .Returns(true);

        _tcpConnectionSnapshotsMock
            .Setup(dict => dict[_transportLayerConnection])
            .Returns(expectedTcpConnectionSnapshot.Object);

        // Act
        var tcpConnectionSnapshot = _sut.ProcessPacket(capturedPacket);

        // Assert
        tcpConnectionSnapshot.Should().BeEquivalentTo(expectedTcpConnectionSnapshot.Object);

        _tcpConnectionSnapshotsMock.Verify(
            dict => dict.Add(It.IsAny<TransportLayerConnection>(), It.IsAny<TcpConnectionSnapshot>()),
            Times.Never);

        _tcpConnectionSnapshotsMock.Verify(
            dict => dict[_transportLayerConnection],
            Times.Once);

        expectedTcpConnectionSnapshot.Verify(
            s => s.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, timestamp),
            Times.Exactly(2));
    }

    internal class PhysicalFrameMock : PhysicalFrame
    {
    }

    internal class NetworkPacketMock : NetworkPacket
    {
        public override IPAddress SourceAddress => throw new NotImplementedException();

        public override IPAddress DestinationAddress => throw new NotImplementedException();
    }

    internal class TransportSegmentMock : TransportSegment
    {
        public override byte[] Payload => throw new NotImplementedException();
    }
}