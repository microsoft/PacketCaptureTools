// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Application.Tds.Latency.TdsConnectionLatencyAnalysisTests;

public partial class TdsConnectionLatencyAnalysisTests
{
    [Fact]
    public void Process_PacketCapturedDateTimeIsNull_ReturnWithNoAction()
    {
        // Arrange
        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture();
        var tdsConnectionSnapshot = GetTdsConnectionSnapshot();

        // Act
        _sut.Process(capturedPacket, tdsConnectionSnapshot);

        // Assert
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(0);
    }

    [Fact]
    public void Process_TransportConnectionSnapshotIsNotTcpConnectionSnapshot_ReturnWithNoAction()
    {
        // Arrange
        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture();

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture();
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(tcpSegment);

        var tcpConnectionSnapshot = new TransportConnectionSnapshotFake(ipPacket, tcpSegment, _transportLayerConnection1, _packetFlowDetector);

        var tdsConnectionSnapshot = _snapshotFixtureFactory.CreateTdsConnectionSnapshotFixture(
            tcpSegment: tcpSegment,
            tcpConnectionSnapshot: tcpConnectionSnapshot);

        // Act
        _sut.Process(capturedPacket, tdsConnectionSnapshot);

        // Assert
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(0);
    }

    [Fact]
    public void Process_TdsConnectionStateIsUnknown_ReturnWithNoAction()
    {
        // Arrange
        var timestamp = DateTime.UtcNow;

        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(capturedDateTime: timestamp);
        var tdsConnectionSnapshot = GetTdsConnectionSnapshot(
            tdsConnectionState: TdsConnectionState.Unknown,
            tcpConnectionState: TcpConnectionState.Established);

        // Act
        _sut.Process(capturedPacket, tdsConnectionSnapshot);

        // Assert
        _sut.PreLoginToPreLoginResponseAverageLatencies.Count.Should().Be(0);
        _sut.ClientHelloToServerHelloAverageLatencies.Count.Should().Be(0);
        _sut.KeyExchangeToCipherChangeAverageLatencies.Count.Should().Be(0);
        _sut.LoginMessageToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.PreLoginToLoginAckAverageLatencies.Count.Should().Be(0);
        _sut.FailedTdsConnectionMetrics.Count.Should().Be(0);
    }
}