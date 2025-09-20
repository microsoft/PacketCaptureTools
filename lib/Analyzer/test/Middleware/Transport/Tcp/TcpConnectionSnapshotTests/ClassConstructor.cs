// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    [Fact]
    public void ClassConstructor_IpPacketIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "ipPacket";

        // Act
        Func<TcpConnectionSnapshot> function = () => new TcpConnectionSnapshot(
            ipPacket: null!,
            tcpSegment: _tcpSegment,
            transportConnection: _transportLayerConnection,
            packetFlowDetector: _packetFlowDetector);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor_TcpSegmentIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "tcpSegment";

        // Act
        Func<TcpConnectionSnapshot> function = () => new TcpConnectionSnapshot(
            ipPacket: _ipPacket,
            tcpSegment: null!,
            transportConnection: _transportLayerConnection,
            packetFlowDetector: _packetFlowDetector);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor_TcpConnectionIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "transportConnection";

        // Act
        Func<TcpConnectionSnapshot> function = () => new TcpConnectionSnapshot(
            ipPacket: _ipPacket,
            tcpSegment: _tcpSegment,
            transportConnection: null!,
            packetFlowDetector: _packetFlowDetector);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor_PacketFlowDetectorIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "packetFlowDetector";

        // Act
        Func<TcpConnectionSnapshot> function = () => new TcpConnectionSnapshot(
            ipPacket: _ipPacket,
            tcpSegment: _tcpSegment,
            transportConnection: _transportLayerConnection,
            packetFlowDetector: null!);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor_OutgoingPacket_SutIsConstructedCorrectly()
    {
        // Arrange
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        // Assert
        sut.TransportConnection.Should().Be(_transportLayerConnection);
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.IncomingLastSeenSequenceNumber.Should().Be(null);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(null);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(LastSeenSequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(LastSeenAcknowledgementNumber);
    }

    [Fact]
    public void ClassConstructor_IncomingPacket_SutIsConstructedCorrectly()
    {
        // Arrange
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        // Assert
        sut.TransportConnection.Should().Be(_transportLayerConnection);
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.IncomingLastSeenSequenceNumber.Should().Be(LastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(LastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(null);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(null);
    }
}