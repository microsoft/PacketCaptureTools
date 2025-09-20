// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class FirstFinishAcknowledgedTcpStateTests
{
    private readonly FirstFinishAcknowledgedTcpState _sut;

    public FirstFinishAcknowledgedTcpStateTests()
    {
        _sut = new FirstFinishAcknowledgedTcpState();
    }

    [Fact]
    public void GetNextTcpState_FinIsTrue_ReturnsSecondFinishSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(fin: true);

        var expectedNextTcpState = new SecondFinishSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_FinIsFalse_ReturnsFirstFinishAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(fin: false);

        var expectedNextTcpState = new FirstFinishAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}