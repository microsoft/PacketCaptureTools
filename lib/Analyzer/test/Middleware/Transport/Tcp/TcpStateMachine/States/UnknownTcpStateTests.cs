// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class UnknownTcpStateTests
{
    private readonly UnknownTcpState _sut;

    public UnknownTcpStateTests()
    {
        _sut = new UnknownTcpState();
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueAckIsFalse_ReturnsSynSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, ack: false);

        var expectedNextTcpState = new SynSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
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
    public void GetNextTcpState_FinIsTrueAckIsTrue_ReturnsClosedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(fin: true, ack: true);

        var expectedNextTcpState = new ClosedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsFalseFinIsFalseAckIsTrue_ReturnsAssumedEstablishedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: false, fin: false, ack: true);

        var expectedNextTcpState = new AssumedEstablishedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsFalseFinOrAckIsFalse_ReturnsUnknownTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: false, fin: false, ack: false);

        var expectedNextTcpState = new UnknownTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}