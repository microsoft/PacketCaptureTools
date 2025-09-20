// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    private const string IsDuplicateOutgoingMethodName = "IsDuplicateOutgoing";

    private bool InvokeIsDuplicateOutgoingMethod(TcpConnectionSnapshot tcpConnectionSnapshot, TcpSegment tcpSegment, out bool isDuplicateAck)
    {
        var arguments = new object[] { tcpSegment, false };

        var result = (bool)GetMethodInfo(IsDuplicateOutgoingMethodName)!.Invoke(tcpConnectionSnapshot, arguments)!;

        isDuplicateAck = (bool)arguments[1];

        return result;
    }

    [Theory]
    [InlineData(1, 1, 1, 2, false, false, 0, false, false)]
    [InlineData(1, 1, 2, 1, false, false, 0, false, false)]
    [InlineData(1, 1, 1, 1, false, false, 0, false, false)]
    [InlineData(1, 1, 1, 1, true, false, 0, true, true)]
    [InlineData(1, 1, 1, 2, false, false, 1, false, false)]
    [InlineData(1, 1, 2, 1, false, false, 1, false, false)]
    [InlineData(1, 1, 1, 1, false, false, 1, false, false)]
    [InlineData(1, 1, 1, 1, false, true, 1, true, false)]
    public void IsDuplicateOutgoing(
        uint outgoingLastSeenSequenceNumber,
        uint outgoingLastSeenAcknowledgementNumber,
        uint tcpSegmentSequenceNumber,
        uint tcpSegmentAcknowledgementNumber,
        bool outgoingSequenceNumberHadZeroPayload,
        bool outgoingSequenceNumberHadNonZeroPayload,
        uint payloadSize,
        bool expectedResult,
        bool expectedIsDuplicateAck)
    {
        // Arrange
        var sut = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection,
            outgoingLastSeenSequenceNumber: outgoingLastSeenSequenceNumber,
            outgoingLastSeenAcknowledgementNumber: outgoingLastSeenAcknowledgementNumber,
            outgoingSequenceNumberHadZeroPayload: outgoingSequenceNumberHadZeroPayload,
            outgoingSequenceNumberHadNonZeroPayload: outgoingSequenceNumberHadNonZeroPayload);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: tcpSegmentSequenceNumber,
            acknowledgementNumber: tcpSegmentAcknowledgementNumber,
            payloadSize: payloadSize);

        // Act
        var result = InvokeIsDuplicateOutgoingMethod(sut, tcpSegment, out var isDuplicateAck);

        // Assert
        result.Should().Be(expectedResult);
        isDuplicateAck.Should().Be(expectedIsDuplicateAck);
    }
}