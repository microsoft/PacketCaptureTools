// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    private const string IsDuplicateIncomingMethodName = "IsDuplicateIncoming";

    private bool InvokeIsDuplicateIncomingMethod(TcpConnectionSnapshot tcpConnectionSnapshot, TcpSegment tcpSegment)
    {
        var arguments = new object[] { tcpSegment };

        return (bool)GetMethodInfo(IsDuplicateIncomingMethodName)!.Invoke(tcpConnectionSnapshot, arguments)!;
    }

    [Theory]
    [InlineData(1, 2, false, 0, false)]
    [InlineData(2, 1, false, 0, false)]
    [InlineData(1, 1, false, 0, false)]
    [InlineData(1, 1, true, 0, false)]
    [InlineData(1, 1, false, 1, false)]
    [InlineData(1, 1, true, 1, true)]
    public void IsDuplicateIncoming1(
        uint incomingLastSeenSequenceNumber,
        uint tcpSegmentSequenceNumber,
        bool incomingSequenceNumberHadPayload,
        uint payloadSize,
        bool expectedResult)
    {
        // Arrange
        var sut = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection,
            incomingLastSeenSequenceNumber: incomingLastSeenSequenceNumber,
            incomingSequenceNumberHadPayload: incomingSequenceNumberHadPayload);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sequenceNumber: tcpSegmentSequenceNumber,
            payloadSize: payloadSize);

        // Act
        var result = InvokeIsDuplicateIncomingMethod(sut, tcpSegment);

        // Assert
        result.Should().Be(expectedResult);
    }
}