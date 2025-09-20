// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class SynAcknowledgedTcpStateTests
{
    private readonly SynAcknowledgedTcpState _sut;

    public SynAcknowledgedTcpStateTests()
    {
        _sut = new SynAcknowledgedTcpState();
    }

    [Fact]
    public void GetNextTcpState_AckIsTrue_ReturnsSimultaneousOpenFirstSynAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: true);

        var expectedNextTcpState = new EstablishedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_AckIsFalse_ReturnsSynAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(ack: false);

        var expectedNextTcpState = new SynAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}