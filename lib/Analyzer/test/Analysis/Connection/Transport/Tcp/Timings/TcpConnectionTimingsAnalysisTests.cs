// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Transport.Tcp.Timings;

public class TcpConnectionTimingsAnalysisTests
{
    private const string SourceIpAddress = "192.168.1.1";
    private const int SourcePort = 1;

    private const string DestinationIpAddress1 = "192.168.0.1";
    private const int DestinationPort1 = 2;

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        IPAddress.Parse(SourceIpAddress)
    };

    private readonly TcpConnectionTimingsAnalysis _sut;

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly TransportLayerConnection _transportLayerConnection1;

    public TcpConnectionTimingsAnalysisTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _transportLayerConnection1 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress1),
            sourcePort: SourcePort,
            destinationPort: DestinationPort1);

        _sut = new TcpConnectionTimingsAnalysis();
    }

    [Fact]
    public void Process_MultipleConnections()
    {
        // Arrange
        var timestampNow = DateTime.UtcNow;

        var synTcpCapturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            capturedDateTime: timestampNow);

        var synTcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.SynSent,
            lastPacketTcpFlags: new TcpFlags(syn: true));

        var rstTcpCapturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            capturedDateTime: timestampNow.Add(TimeSpan.FromMilliseconds(200)));

        var rstTcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.Closed,
            lastPacketTcpFlags: new TcpFlags(rst: true));

        var synTcpCapturedPacket2 = _packetFixtureFactory.CreateCapturedPacketFixture(
            capturedDateTime: timestampNow.Add(TimeSpan.FromSeconds(1)));

        var synTcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.SynSent,
            lastPacketTcpFlags: new TcpFlags(syn: true));

        var estTcpCapturedPacket2 = _packetFixtureFactory.CreateCapturedPacketFixture(
            capturedDateTime: timestampNow.Add(TimeSpan.FromSeconds(10)));

        var estTcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.Established,
            lastPacketTcpFlags: new TcpFlags());

        var rstTcpCapturedPacket2 = _packetFixtureFactory.CreateCapturedPacketFixture(
            capturedDateTime: timestampNow.Add(TimeSpan.FromSeconds(20)));

        var rstTcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            tcpConnectionState: TcpConnectionState.Closed,
            lastPacketTcpFlags: new TcpFlags(rst: true));

        var capturedPacketToSkip = _packetFixtureFactory.CreateCapturedPacketFixture();

        // Act
        _sut.Process(synTcpCapturedPacket, synTcpConnectionSnapshot);
        _sut.Process(rstTcpCapturedPacket, rstTcpConnectionSnapshot);
        _sut.Process(synTcpCapturedPacket2, synTcpConnectionSnapshot2);
        _sut.Process(estTcpCapturedPacket2, estTcpConnectionSnapshot2);
        _sut.Process(rstTcpCapturedPacket2, rstTcpConnectionSnapshot2);

        _sut.Process(capturedPacketToSkip, rstTcpConnectionSnapshot);

        // Assert
        _sut.ConnectionDurations.GetTimestampForPercentile(75)
            .Should()
            .Be("19 s");
        _sut.ConnectionDurations.GetTimestampForPercentile(25)
            .Should()
            .Be("200 ms");
        _sut.ResetAndNextSynDurations.GetTimestampForPercentile(30)
            .Should()
            .Be("800 ms");
        _sut.ResetAndNextSynDurations.GetTimestampForPercentile(70)
            .Should()
            .Be("800 ms");
        _sut.HandshakeDurations.GetTimestampForPercentile(80)
            .Should()
            .Be("9 s");
        _sut.HandshakeDurations.GetTimestampForPercentile(10)
            .Should()
            .Be("9 s");
    }
}