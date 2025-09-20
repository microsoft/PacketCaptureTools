// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    private const string UpdateLastSeenNumbersMethodName = "UpdateLastSeenNumbers";

    private void InvokeUpdateLastSeenNumbersMethod(TcpConnectionSnapshot tcpConnectionSnapshot, TcpSegment tcpSegment, PacketDirection packetDirection)
    {
        var arguments = new object[] { tcpSegment, packetDirection };

        GetMethodInfo(UpdateLastSeenNumbersMethodName)!.Invoke(tcpConnectionSnapshot, arguments);
    }

    [Fact]
    public void UpdateLastSeenNumbersMethodName_IncomingPacket_UpdateIncomingLastSeenNumbers()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Outgoing);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: 100,
            acknowledgementNumber: 200,
            dataOffset: 20);

        var expectedOutgoingLastSeenSequenceNumber = sut.OutgoingLastSeenSequenceNumber;
        var expectedOutgoingLastSeenAcknowledgementNumber = sut.OutgoingLastSeenAcknowledgementNumber;
        var expectedIncomingNextExpectedSequenceNumber = (uint)(tcpSegment.SequenceNumber + tcpSegment.NonTruncatedPayloadLength);

        // Act
        InvokeUpdateLastSeenNumbersMethod(sut, tcpSegment, PacketDirection.Incoming);

        // Assert
        sut.IncomingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
        sut.IncomingNextExpectedSequenceNumber.Should().Be(expectedIncomingNextExpectedSequenceNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(expectedOutgoingLastSeenSequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(expectedOutgoingLastSeenAcknowledgementNumber);
    }

    [Fact]
    public void UpdateLastSeenNumbersMethodName_OutgoingPacket_UpdateOutgoingLastSeenNumbers()
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(PacketDirection.Incoming);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: 100,
            acknowledgementNumber: 200);

        var expectedIncomingLastSeenSequenceNumber = sut.IncomingLastSeenSequenceNumber;
        var expectedIncomingLastSeenAcknowledgementNumber = sut.IncomingLastSeenAcknowledgementNumber;

        // Act
        InvokeUpdateLastSeenNumbersMethod(sut, tcpSegment, PacketDirection.Outgoing);

        // Assert
        sut.IncomingLastSeenSequenceNumber.Should().Be(expectedIncomingLastSeenSequenceNumber);
        sut.IncomingLastSeenAcknowledgementNumber.Should().Be(expectedIncomingLastSeenAcknowledgementNumber);
        sut.OutgoingLastSeenSequenceNumber.Should().Be(tcpSegment.SequenceNumber);
        sut.OutgoingLastSeenAcknowledgementNumber.Should().Be(tcpSegment.AckNumber);
    }
}