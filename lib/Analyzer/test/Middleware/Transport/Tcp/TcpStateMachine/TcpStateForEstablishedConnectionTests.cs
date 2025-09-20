// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp.TcpStateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpStateMachine;

public class TcpStateForEstablishedConnectionTests
{
    private readonly TcpStateForEstablishedConnectionMock _sut;

    public TcpStateForEstablishedConnectionTests()
    {
        _sut = new TcpStateForEstablishedConnectionMock();
    }

    [Fact]
    public void GetNextTcpState_SynIsTrue_ReturnsTcpStateForEstablishedConnectionMock()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: true);

        var expectedNextTcpState = new TcpStateForEstablishedConnectionMock();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTcpState_SynIsFalse_ReturnsUnknownTcpState()
    {
        // Arrange
        var tcpFlags = new TcpFlags(syn: false);

        var expectedNextTcpState = new UnknownTcpState();

        // Act
        var nextTcpState = _sut.GetNextState(tcpFlags);

        // Assert
        nextTcpState.Should().BeEquivalentTo(expectedNextTcpState, options => options.IncludingInternalProperties());
    }

    internal class TcpStateForEstablishedConnectionMock : TcpStateForEstablishedConnection
    {
        internal override TcpConnectionState TcpConnectionState => TcpConnectionState.Unknown;

        protected override TcpState GetNextTcpStateForEstablishedConnection(TcpFlags tcpFlags)
        {
            return new UnknownTcpState();
        }
    }
}