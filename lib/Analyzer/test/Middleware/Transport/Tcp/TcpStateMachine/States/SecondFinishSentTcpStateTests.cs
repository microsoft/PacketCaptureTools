// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class SecondFinishSentTcpStateTests
{
    private readonly SecondFinishSentTcpState _sut;

    public SecondFinishSentTcpStateTests()
    {
        _sut = new SecondFinishSentTcpState();
    }

    [Fact]
    public void GetNextTcpState_AckIsTrue_ReturnsClosedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: true);

        var expectedNextTcpState = new ClosedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_AckIsFalse_ReturnsSecondFinishSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: false);

        var expectedNextTcpState = new SecondFinishSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}