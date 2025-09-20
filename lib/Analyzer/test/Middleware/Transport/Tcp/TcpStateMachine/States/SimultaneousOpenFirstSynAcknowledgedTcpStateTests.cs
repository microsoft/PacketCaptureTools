// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class SimultaneousOpenFirstSynAcknowledgedTcpStateTests
{
    private readonly SimultaneousOpenFirstSynAcknowledgedTcpState _sut;

    public SimultaneousOpenFirstSynAcknowledgedTcpStateTests()
    {
        _sut = new SimultaneousOpenFirstSynAcknowledgedTcpState();
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueAckIsTrue_ReturnsEstablishedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, ack: true);

        var expectedNextTcpState = new EstablishedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void GetNextTcpState_OtherFlagCombinations_ReturnsSimultaneousOpenFirstSynAcknowledgedTcpState(bool syn, bool ack)
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: syn, ack: ack);

        var expectedNextTcpState = new SimultaneousOpenFirstSynAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}