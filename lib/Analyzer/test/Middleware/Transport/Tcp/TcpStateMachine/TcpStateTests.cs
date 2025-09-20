// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine;

public class TcpStateTests
{
    private readonly TcpStateMock _sut;

    public TcpStateTests()
    {
        _sut = new TcpStateMock();
    }

    [Fact]
    public void GetNextTcpState_RstIsTrue_ReturnsClosedTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(rst: true);

        var expectedNextTcpState = new ClosedTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsTrueFinIsTrue_ReturnsTcpStateMock()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true, fin: true);

        var expectedNextTcpState = new TcpStateMock();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void GetNextTcpState_OtherFlagCombinations_ReturnsUnknownTcpState(bool syn, bool fin)
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: syn, fin: fin);

        var expectedNextTcpState = new UnknownTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    internal class TcpStateMock : TcpState
    {
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.Unknown;

        protected override TcpState GetNextTcpState(TcpFlags tcpFlags)
        {
            return new UnknownTcpState();
        }
    }
}