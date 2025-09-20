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
    [Fact]
    public void UpdateTcpConnectionSnapshot_IncomingPacketIsDuplicate_IncrementIncomingDuplicatePackets()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: LastSeenSequenceNumber,
            acknowledgementNumber: LastSeenAcknowledgementNumber,
            payloadSize: TcpSegmentPayloadSize);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.DestinationIpAddress,
            destinationIpAddress: _transportLayerConnection.SourceIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;
        var expectedOutgoingLastSeenSequenceNumber = sut.OutgoingLastSeenSequenceNumber;
        var expectedOutgoingLastSeenAcknowledgementNumber = sut.OutgoingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(1);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.OutgoingDuplicatePackets.Should().Be(0);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(0);
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(expectedOutgoingLastSeenSequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(expectedOutgoingLastSeenAcknowledgementNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateTcpConnectionSnapshot_IncomingPacketIsOutOfOrder_IncrementIncomingOutOfOrderPackets()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: (uint)(sut.IncomingNextExpectedSequenceNumber! - 1),
            acknowledgementNumber: LastSeenAcknowledgementNumber);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.DestinationIpAddress,
            destinationIpAddress: _transportLayerConnection.SourceIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;
        var expectedOutgoingLastSeenSequenceNumber = sut.OutgoingLastSeenSequenceNumber;
        var expectedOutgoingLastSeenAcknowledgementNumber = sut.OutgoingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(1);
        sut.OutgoingDuplicatePackets.Should().Be(0);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(0);
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(expectedOutgoingLastSeenSequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(expectedOutgoingLastSeenAcknowledgementNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateTcpConnectionSnapshot_IncomingPacketNotDuplicateNotOutOfOrder_UpdateAllMetrics()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: LastSeenAcknowledgementNumber,
            acknowledgementNumber: LastSeenAcknowledgementNumber + 1,
            tcpFlags: new TcpFlags(syn: true, ack: true));

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.DestinationIpAddress,
            destinationIpAddress: _transportLayerConnection.SourceIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedOutgoingLastSeenSequenceNumber = sut.OutgoingLastSeenSequenceNumber;
        var expectedOutgoingLastSeenAcknowledgementNumber = sut.OutgoingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynAcknowledged;
        var expectedLastRoundTripTime = packetCaptureTimestamp.Subtract(_packetCaptureTimestamp);

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.OutgoingDuplicatePackets.Should().Be(0);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(0);
        sut.IncomingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(expectedOutgoingLastSeenSequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(expectedOutgoingLastSeenAcknowledgementNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(expectedLastRoundTripTime);
    }

    [Fact]
    public void UpdateTcpConnectionSnapshot_OutgoingPacketIsDuplicate_IncrementOutgoingDuplicatePackets()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: LastSeenSequenceNumber,
            acknowledgementNumber: LastSeenAcknowledgementNumber,
            payloadSize: TcpSegmentPayloadSize);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.SourceIpAddress,
            destinationIpAddress: _transportLayerConnection.DestinationIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.OutgoingDuplicatePackets.Should().Be(1);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(0);
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateTcpConnectionSnapshot_OutgoingPacketIsDuplicateAcknowledgement_IncrementOutgoingDuplicateAcknowledgements()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(
            packetDirection: PacketDirection.Outgoing,
            tcpSegmentDataOffset: 0,
            tcpSegmentPayloadSize: 0);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: LastSeenSequenceNumber,
            acknowledgementNumber: LastSeenAcknowledgementNumber,
            payloadSize: 0);

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.SourceIpAddress,
            destinationIpAddress: _transportLayerConnection.DestinationIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynSent;

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.OutgoingDuplicatePackets.Should().Be(0);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(1);
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(default);
    }

    [Fact]
    public void UpdateTcpConnectionSnapshot_OutgoingPacket_UpdateAllMetrics()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            tcpFlags: new TcpFlags(syn: true, ack: true));

        var iPv4Packet = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _transportLayerConnection.SourceIpAddress,
            destinationIpAddress: _transportLayerConnection.DestinationIpAddress);

        var packetCaptureTimestamp = DateTime.UtcNow;

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;
        var expectedTcpConnectionState = TcpConnectionState.SynAcknowledged;

        // Act
        sut.UpdateTcpConnectionSnapshot(tcpSegment, iPv4Packet, packetCaptureTimestamp);

        // Assert
        sut.IncomingDuplicatePackets.Should().Be(0);
        sut.OutOfOrderPackets.Should().Be(0);
        sut.OutgoingDuplicatePackets.Should().Be(0);
        sut.OutgoingDuplicateAcknowledgements.Should().Be(0);
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
        sut.TcpConnectionState.Should().Be(expectedTcpConnectionState);
        sut.LastRoundTripTime.Should().Be(default);
    }
}