// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class FirstFinishSentTcpStateTests
{
    private readonly FirstFinishSentTcpState _sut;

    public FirstFinishSentTcpStateTests()
    {
        _sut = new FirstFinishSentTcpState();
    }

    [Fact]
    public void GetNextTcpState_AckIsTrueFinIsFalse_ReturnsFirstFinishAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: true, fin: false);

        var expectedNextTcpState = new FirstFinishAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_AckIsTrueFinIsTrue_ReturnsSecondFinishSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: true, fin: true);

        var expectedNextTcpState = new SecondFinishSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_AckIsFalse_ReturnsFirstFinishSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: false);

        var expectedNextTcpState = new FirstFinishSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}