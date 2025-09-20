// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class SynSentTcpStateTests
{
    private readonly SynSentTcpState _sut;

    public SynSentTcpStateTests()
    {
        _sut = new SynSentTcpState();
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueAckIsTrue_ReturnsSynAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, ack: true);

        var expectedNextTcpState = new SynAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueAckIsFalse_ReturnsSimultaneousOpenSecondSynReceivedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, ack: false);

        var expectedNextTcpState = new SimultaneousOpenSecondSynReceivedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsFalse_ReturnsSynSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: false);

        var expectedNextTcpState = new SynSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}