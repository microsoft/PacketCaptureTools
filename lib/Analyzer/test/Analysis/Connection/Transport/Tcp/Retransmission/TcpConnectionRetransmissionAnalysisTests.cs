// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Transport.Tcp.Retransmission;

public class TcpConnectionRetransmissionAnalysisTests
{
    private const int SourcePort = 1;
    private const int DestinationPort = 2;

    private const string SourceIpAddress = "192.168.1.1";
    private const string SourceIpv6Address = "fec0::1";
    private const string DestinationIpAddress1 = "192.168.0.1";
    private const string DestinationIpAddress2 = "192.168.0.2";
    private const string DestinationIpAddress3 = "192.168.0.3";
    private const string DestinationIpv6Address1 = "fec0::11";
    private const string DestinationIpv6Address2 = "fec0::12";
    private const string DestinationIpv6Address3 = "fec0::13";
    
    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress>
    {
        IPAddress.Parse(SourceIpAddress),
        IPAddress.Parse(SourceIpv6Address),
    };

    private readonly TcpConnectionRetransmissionAnalysis _sut;

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    
    public TcpConnectionRetransmissionAnalysisTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        
        _sut = new TcpConnectionRetransmissionAnalysis();
    }

    [Theory]
    [InlineData(SourceIpAddress, DestinationIpAddress1)]
    [InlineData(SourceIpv6Address, DestinationIpv6Address1)]
    public void Process_SingleSnapshot_SingleRetransmissionForIpAndTime(string sourceIpAddress, string destinationIpAddress)
    {
        // Arrange
        var timestampNow = DateTime.UtcNow;

        var transportLayerConnection = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress);

        var capturedPacket = CreateCapturedPacket(
            sourceIp: transportLayerConnection.SourceIpAddress,
            destinationIp: transportLayerConnection.DestinationIpAddress,
            timestamp: timestampNow);

        var tcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        // Act
        _sut.Process(capturedPacket, tcpConnectionSnapshot);

        // Assert
        _sut.RetransmissionsByIpAddress.Count.Should().Be(1);
        _sut.RetransmissionsByTime.Count.Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByTime[timestampNow.TruncateToSeconds()].Should().Be(1);
    }

    [Theory]
    [InlineData(SourceIpAddress, DestinationIpAddress1, DestinationIpAddress2, DestinationIpAddress3)]
    [InlineData(SourceIpv6Address, DestinationIpv6Address1, DestinationIpv6Address2, DestinationIpv6Address3)]
    public void Process_MultipleSnapshotsDifferentIpAddressesSameTimes_SingleRetransmissionForEachIpMultipleRetransmissionsForTime(
        string sourceIpAddress,
        string destinationIpAddress1,
        string destinationIpAddress2,
        string destinationIpAddress3)
    {
        // Arrange
        var timestampNow = DateTime.UtcNow;

        var transportLayerConnection1 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress1);

        var capturedPacket1 = CreateCapturedPacket(
            sourceIp: transportLayerConnection1.SourceIpAddress,
            destinationIp: transportLayerConnection1.DestinationIpAddress,
            timestamp: timestampNow);

        var tcpConnectionSnapshot1 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var transportLayerConnection2 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress2);

        var capturedPacket2 = CreateCapturedPacket(
            sourceIp: transportLayerConnection2.SourceIpAddress,
            destinationIp: transportLayerConnection2.DestinationIpAddress,
            timestamp: timestampNow);

        var tcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var transportLayerConnection3 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress3);


        var capturedPacket3 = CreateCapturedPacket(
            sourceIp: transportLayerConnection3.SourceIpAddress,
            destinationIp: transportLayerConnection3.DestinationIpAddress,
            timestamp: timestampNow);


        var tcpConnectionSnapshot3 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot1);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot2);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot3);

        // Assert
        _sut.RetransmissionsByIpAddress.Count.Should().Be(3);
        _sut.RetransmissionsByTime.Count.Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection1.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection2.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection3.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByTime[timestampNow.TruncateToSeconds()].Should().Be(3);
    }

    [Theory]
    [InlineData(SourceIpAddress, DestinationIpAddress1)]
    [InlineData(SourceIpv6Address, DestinationIpv6Address1)]
    public void Process_MultipleSnapshotsSameIpAddressDifferentTimes_MultipleRetransmissionsForIpSingleRetransmissionForEachTime(string sourceIpAddress, string destinationIpAddress1)
    {
        // Arrange
        var timestampNow = DateTime.UtcNow;

        var transportLayerConnection = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress1);

        var capturedPacket1 = CreateCapturedPacket(
            sourceIp: transportLayerConnection.SourceIpAddress,
            destinationIp: transportLayerConnection.DestinationIpAddress,
            timestamp: timestampNow);
        
        var tcpConnectionSnapshot1 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var capturedPacket2 = CreateCapturedPacket(
            sourceIp: transportLayerConnection.SourceIpAddress,
            destinationIp: transportLayerConnection.DestinationIpAddress,
            timestamp: timestampNow.AddSeconds(1));

        var tcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var capturedPacket3 = CreateCapturedPacket(
            sourceIp: transportLayerConnection.SourceIpAddress,
            destinationIp: transportLayerConnection.DestinationIpAddress,
            timestamp: timestampNow.AddSeconds(2));

        var tcpConnectionSnapshot3 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot1);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot2);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot3);

        // Assert
        capturedPacket1.CapturedDateTime.Should().NotBeNull();
        capturedPacket2.CapturedDateTime.Should().NotBeNull();
        capturedPacket3.CapturedDateTime.Should().NotBeNull();

        _sut.RetransmissionsByIpAddress.Count.Should().Be(1);
        _sut.RetransmissionsByTime.Count.Should().Be(3);
        _sut.RetransmissionsByIpAddress[transportLayerConnection.DestinationIpAddress].Should().Be(3);
        _sut.RetransmissionsByTime[capturedPacket1.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
        _sut.RetransmissionsByTime[capturedPacket2.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
        _sut.RetransmissionsByTime[capturedPacket3.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
    }


    [Theory]
    [InlineData(SourceIpAddress, DestinationIpAddress1, DestinationIpAddress2, DestinationIpAddress3)]
    [InlineData(SourceIpv6Address, DestinationIpv6Address1, DestinationIpv6Address2, DestinationIpv6Address3)]
    public void Process_MultipleSnapshotsDifferentIpAddressesAndTimes_SingleRetransmissionsForEachIpAndTime(
        string sourceIpAddress,
        string destinationIpAddress1,
        string destinationIpAddress2,
        string destinationIpAddress3)
    {
        // Arrange
        var timestampNow = DateTime.UtcNow;
        
        var transportLayerConnection1 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress1);
        
        var capturedPacket1 = CreateCapturedPacket(
            sourceIp: transportLayerConnection1.SourceIpAddress,
            destinationIp: transportLayerConnection1.DestinationIpAddress,
            timestamp: timestampNow);

        var tcpConnectionSnapshot1 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var transportLayerConnection2 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress2);

        var capturedPacket2 = CreateCapturedPacket(
            sourceIp: transportLayerConnection2.SourceIpAddress,
            destinationIp: transportLayerConnection2.DestinationIpAddress,
            timestamp: timestampNow.AddSeconds(1));

        var tcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        var transportLayerConnection3 = GetTransportLayerConnection(sourceIpAddress, destinationIpAddress3);

        var capturedPacket3 = CreateCapturedPacket(
            sourceIp: transportLayerConnection3.SourceIpAddress,
            destinationIp: transportLayerConnection3.DestinationIpAddress,
            timestamp: timestampNow.AddSeconds(2));

        var tcpConnectionSnapshot3 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector,
            lastPacketIsOutgoingDuplicate: true);

        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot1);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot2);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot3);

        // Assert
        capturedPacket1.CapturedDateTime.Should().NotBeNull();
        capturedPacket2.CapturedDateTime.Should().NotBeNull();
        capturedPacket3.CapturedDateTime.Should().NotBeNull();

        _sut.RetransmissionsByIpAddress.Count.Should().Be(3);
        _sut.RetransmissionsByTime.Count.Should().Be(3);
        _sut.RetransmissionsByIpAddress[transportLayerConnection1.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection2.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByIpAddress[transportLayerConnection3.DestinationIpAddress].Should().Be(1);
        _sut.RetransmissionsByTime[capturedPacket1.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
        _sut.RetransmissionsByTime[capturedPacket2.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
        _sut.RetransmissionsByTime[capturedPacket3.CapturedDateTime.Value.TruncateToSeconds()].Should().Be(1);
    }

    private CapturedPacket CreateCapturedPacket(IPAddress sourceIp, IPAddress destinationIp, DateTime timestamp)
    {
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: null,
            sourceIpAddress: sourceIp,
            destinationIpAddress: destinationIp);
        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            networkPacket: ipPacket,
            capturedDateTime: timestamp);
        return capturedPacket;
    }
    
    private TransportLayerConnection GetTransportLayerConnection(string sourceIpAddress, string destinationIpAddress)
    {
        return new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(sourceIpAddress),
            destinationIpAddress: IPAddress.Parse(destinationIpAddress),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);
    }
}