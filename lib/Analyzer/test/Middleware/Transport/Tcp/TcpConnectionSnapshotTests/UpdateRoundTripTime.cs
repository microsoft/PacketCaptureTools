// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    private const string UpdateRoundTripTimeMethodName = "UpdateRoundTripTime";

    private void InvokeUpdateRoundTripTimeMethod(TcpConnectionSnapshot tcpConnectionSnapshot, DateTime? packetCaptureTimestamp, TcpSegment tcpSegment, PacketDirection packetDirection)
    {
        var arguments = new object?[] { packetCaptureTimestamp, tcpSegment, packetDirection };

        GetMethodInfo(UpdateRoundTripTimeMethodName)!.Invoke(tcpConnectionSnapshot, arguments);
    }

    [Fact]
    public void UpdateRoundTripTime_OutgoingPacketIncomingPacket_UpdateLastRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var outgoingTcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture();

        var incomingTcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        var outgoingTimestamp = _packetCaptureTimestamp.AddSeconds(1);
        var incomingTimestamp = _packetCaptureTimestamp.AddSeconds(2);

        var expectedRoundTripTime = incomingTimestamp.Subtract(outgoingTimestamp);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp, outgoingTcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp, incomingTcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(expectedRoundTripTime);
    }

    [Fact]
    public void UpdateRoundTripTime_OutgoingPacketIncomingPacketWithoutIncomingLastSeenAcknowledgementNumber_UpdateLastRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        var incomingTcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture();

        var incomingTimestamp = _packetCaptureTimestamp.AddSeconds(1);

        var expectedRoundTripTime = incomingTimestamp.Subtract(_packetCaptureTimestamp);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp, incomingTcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(expectedRoundTripTime);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleOutgoingPacketIncomingPacket_LastMessageRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        var outgoingTimestamp1 = _packetCaptureTimestamp.AddSeconds(1);
        var incomingTimestamp1 = _packetCaptureTimestamp.AddSeconds(2);
        var outgoingTimestamp2 = _packetCaptureTimestamp.AddSeconds(3);
        var incomingTimestamp2 = _packetCaptureTimestamp.AddSeconds(4);
        var outgoingTimestamp3 = _packetCaptureTimestamp.AddSeconds(5);
        var incomingTimestamp3 = _packetCaptureTimestamp.AddSeconds(6);

        var expectedRoundTripTime = incomingTimestamp3.Subtract(outgoingTimestamp3);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp1, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp1, tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp2, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp2, tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp3, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp3, tcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(expectedRoundTripTime);
    }

    [Fact]
    public void UpdateRoundTripTime_IncomingPacketOutgoingPacket_DoNotUpdateLastRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(1), tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(2), tcpSegment, PacketDirection.Outgoing);

        // Assert
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleOutgoingPackets_DoNotUpdateLastRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(1), tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(2), tcpSegment, PacketDirection.Outgoing);

        // Assert
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleIncomingPackets_DoNotUpdateLastRoundTripTime()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(1), tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, _packetCaptureTimestamp.AddSeconds(2), tcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleOutgoingPacketsIncomingPacket_CalculateRttFromTheFirstOutgoingPacket()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        var outgoingTimestamp1 = _packetCaptureTimestamp.AddSeconds(1);
        var outgoingTimestamp2 = _packetCaptureTimestamp.AddSeconds(2);
        var incomingTimestamp = _packetCaptureTimestamp.AddSeconds(3);

        var expectedRoundTripTime = incomingTimestamp.Subtract(outgoingTimestamp1);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp1, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp2, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp, tcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(expectedRoundTripTime);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleOutgoingPacketsIncomingPacketOutgoingPacket_CalculateRttFromTheFirstOutgoingPacket()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        var outgoingTimestamp1 = _packetCaptureTimestamp.AddSeconds(1);
        var outgoingTimestamp2 = _packetCaptureTimestamp.AddSeconds(2);
        var incomingTimestamp = _packetCaptureTimestamp.AddSeconds(3);
        var outgoingTimestamp3 = _packetCaptureTimestamp.AddSeconds(4);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp1, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp2, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp, tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp3, tcpSegment, PacketDirection.Outgoing);

        // Assert
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateRoundTripTime_MultipleOutgoingPacketsIncomingPacketOutgoingPacketIncomingPacket_CalculateRttFromTheFirstOutgoingPacket()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            acknowledgementNumber: sut.IncomingLastSeenAcknowledgementNumber!.Value + 1);

        var outgoingTimestamp1 = _packetCaptureTimestamp.AddSeconds(1);
        var outgoingTimestamp2 = _packetCaptureTimestamp.AddSeconds(2);
        var incomingTimestamp1 = _packetCaptureTimestamp.AddSeconds(3);
        var outgoingTimestamp3 = _packetCaptureTimestamp.AddSeconds(4);
        var incomingTimestamp2 = _packetCaptureTimestamp.AddSeconds(5);

        var expectedRoundTripTime = incomingTimestamp2.Subtract(outgoingTimestamp3);

        // Act
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp1, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp2, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp1, tcpSegment, PacketDirection.Incoming);
        InvokeUpdateRoundTripTimeMethod(sut, outgoingTimestamp3, tcpSegment, PacketDirection.Outgoing);
        InvokeUpdateRoundTripTimeMethod(sut, incomingTimestamp2, tcpSegment, PacketDirection.Incoming);

        // Assert
        sut.LastRoundTripTime.Should().Be(expectedRoundTripTime);
    }
}