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
    private const string IsOutOfOrderMethodName = "IsOutOfOrder";

    private bool InvokeIsOutOfOrderMethod(TcpConnectionSnapshot tcpConnectionSnapshot, TcpSegment tcpSegment)
    {
        var argumentTypes = new[] { typeof(TcpSegment) };
        var arguments = new object[] { tcpSegment };

        return (bool)GetMethodInfo(IsOutOfOrderMethodName, argumentTypes)!.Invoke(tcpConnectionSnapshot, arguments)!;
    }

    [Theory]
    [InlineData(LastSeenSequenceNumber, PacketDirection.Incoming, true)]
    [InlineData(LastSeenSequenceNumber + TcpSegmentPayloadSize, PacketDirection.Incoming, false)]
    [InlineData(LastSeenSequenceNumber + TcpSegmentPayloadSize + 1, PacketDirection.Incoming, false)]
    public void IsOutOfOrder(uint sequenceNumber, PacketDirection lastPacketDirection, bool expectedResult)
    {
        // Arrange
        var sut = GetTcpConnectionSnapshotFixture(lastPacketDirection);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(sequenceNumber: sequenceNumber);

        // Act
        var result = InvokeIsOutOfOrderMethod(sut, tcpSegment);

        // Assert
        result.Should().Be(expectedResult);
    }
}