// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class EstablishedTcpStateTests
{
    private readonly EstablishedTcpState _sut;

    public EstablishedTcpStateTests()
    {
        _sut = new EstablishedTcpState();
    }

    [Fact]
    public void GetNextTcpState_FinIsTrue_ReturnsFirstFinishSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(fin: true);

        var expectedNextTcpState = new FirstFinishSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_FinIsFalse_ReturnsEstablishedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(fin: false);

        var expectedNextTcpState = new EstablishedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}