// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class SimultaneousOpenSecondSynReceivedTcpStateTests
{
    private readonly SimultaneousOpenSecondSynReceivedTcpState _sut;

    public SimultaneousOpenSecondSynReceivedTcpStateTests()
    {
        _sut = new SimultaneousOpenSecondSynReceivedTcpState();
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueAckIsTrue_ReturnsSimultaneousOpenFirstSynAcknowledgedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, ack: true);

        var expectedNextTcpState = new SimultaneousOpenFirstSynAcknowledgedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void GetNextTcpState_OtherFlagCombinations_ReturnsSimultaneousOpenSecondSynReceivedTcpState(bool syn, bool ack)
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: syn, ack: ack);

        var expectedNextTcpState = new SimultaneousOpenSecondSynReceivedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}