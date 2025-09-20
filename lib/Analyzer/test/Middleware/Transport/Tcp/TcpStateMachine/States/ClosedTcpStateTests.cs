// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine.States;

public class ClosedTcpStateTests
{
    private readonly ClosedTcpState _sut;

    public ClosedTcpStateTests()
    {
        _sut = new ClosedTcpState();
    }

    [Fact]
    public void GetNextTcpState_SynIsFalse_ReturnsClosedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: false);

        var expectedNextTcpState = new ClosedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsTrue_ReturnsSynSentTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true);

        var expectedNextTcpState = new SynSentTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }
}