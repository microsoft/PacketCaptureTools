// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection;

public class TdsLoginConnectionAnalysisTests
{
    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress
    };

    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TdsLoginConnectionAnalysis _sut;

    public TdsLoginConnectionAnalysisTests()
    {
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new TdsLoginConnectionAnalysis();
    }

    [Fact]
    public void Test_TdsLoginConnectionAnalysis_Constructor()
    {
        // Given
        var analysis = new TdsLoginConnectionAnalysis();

        // Then
        analysis.ConnectionStates.Should().NotBeNull();
        analysis.ConnectionStates.Should().BeEmpty();
    }

    [Fact]
    public void Process_ClientHelloTdsState_CH_Output()
    {
        // Given
        var packetFactory = new PacketFixtureFactory();

        var tcpSegment1 = packetFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags(psh: true));

        var tcpSegment2 = packetFactory.CreateTcpSegmentFixture(
            sourcePort: 1433,
            destinationPort: 80,
            tcpFlags: new TcpFlags(psh: true));

        var ipPacket1 = packetFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment1,
            destinationIpAddress: _referenceIpAddress,
            sourceIpAddress: _ipv4Address);

        var ipPacket2 = packetFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment1,
            destinationIpAddress: _ipv4Address,
            sourceIpAddress: _referenceIpAddress);

        var transportConnection1 = new TransportLayerConnection(
            sourceIpAddress: ipPacket1.SourceAddress,
            destinationIpAddress: ipPacket1.DestinationAddress,
            sourcePort: tcpSegment1.SourcePort,
            destinationPort: tcpSegment1.DestinationPort);

        var capturedPacket1 = packetFactory.CreateCapturedPacketFixture(
            networkPacket: ipPacket1,
            transportSegment: tcpSegment1,
            capturedDateTime: DateTime.Now);

        var tcpConnectionSnapshot1 = new TcpConnectionSnapshot(
            ipPacket: ipPacket1,
            tcpSegment: tcpSegment1,
            transportConnection: transportConnection1,
            packetFlowDetector: _packetFlowDetector,
            packetCaptureTimestamp: null);

        var connection = new TransportLayerConnection(
            sourceIpAddress: ipPacket1.SourceAddress,
            destinationIpAddress: ipPacket1.DestinationAddress,
            sourcePort: tcpSegment1.SourcePort,
            destinationPort: tcpSegment1.DestinationPort);

        var tdsConnectionSnapshot = new TdsConnectionSnapshot(
            ipPacket: ipPacket1,
            segment: tcpSegment1,
            tcpConnectionSnapshot: tcpConnectionSnapshot1);

        var analysis = new TdsLoginConnectionAnalysis();

        // When
        tdsConnectionSnapshot.UpdateTdsConnectionSnapshot(ipPacket2, tcpSegment2);
        tdsConnectionSnapshot.UpdateTdsConnectionSnapshot(ipPacket1, tcpSegment1);
        analysis.Process(capturedPacket1, tdsConnectionSnapshot);

        // Then
        analysis.ConnectionStates.Should().NotBeNull();
        analysis.ConnectionStates.Count.Should().Be(1);

        analysis.ConnectionStates[connection][0].ConnectionState.Should().Be(TdsConnectionState.ClientHello);
    }
}