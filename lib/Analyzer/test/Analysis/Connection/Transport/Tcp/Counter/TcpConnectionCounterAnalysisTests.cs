// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Transport.Tcp.Counter;

public class TcpConnectionCounterAnalysisTests
{
    private const int SourcePort = 1;
    private const int DestinationPort1 = 1;
    private const int DestinationPort2 = 2;
    private const int DestinationPort3 = 3;

    private static readonly IPAddress SourceIpAddress = IPAddress.Parse("192.168.1.1");
    private static readonly IPAddress DestinationIpAddress1 = IPAddress.Parse("192.168.0.1");
    private static readonly IPAddress DestinationIpAddress2 = IPAddress.Parse("192.168.0.2");
    private static readonly IPAddress DestinationIpAddress3 = IPAddress.Parse("192.168.0.3");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = [SourceIpAddress];

    private readonly TcpConnectionCounterAnalysis _sut;

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly TransportLayerConnection _transportLayerConnection1;
    private readonly TransportLayerConnection _transportLayerConnection2;
    private readonly TransportLayerConnection _transportLayerConnection3;
    private readonly TransportLayerConnection _transportLayerConnection12;
    private readonly TransportLayerConnection _transportLayerConnection13;

    public TcpConnectionCounterAnalysisTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _transportLayerConnection1 = new TransportLayerConnection(
            sourceIpAddress: SourceIpAddress,
            destinationIpAddress: DestinationIpAddress1,
            sourcePort: SourcePort,
            destinationPort: DestinationPort1);

        _transportLayerConnection2 = new TransportLayerConnection(
            sourceIpAddress: SourceIpAddress,
            destinationIpAddress: DestinationIpAddress2,
            sourcePort: SourcePort,
            destinationPort: DestinationPort1);
        
        _transportLayerConnection3 = new TransportLayerConnection(
            sourceIpAddress: SourceIpAddress,
            destinationIpAddress: DestinationIpAddress3,
            sourcePort: SourcePort,
            destinationPort: DestinationPort1);
        
        _transportLayerConnection12 = new TransportLayerConnection(
            sourceIpAddress: SourceIpAddress,
            destinationIpAddress: DestinationIpAddress1,
            sourcePort: SourcePort,
            destinationPort: DestinationPort2);

        _transportLayerConnection13 = new TransportLayerConnection(
            sourceIpAddress: SourceIpAddress,
            destinationIpAddress: DestinationIpAddress1,
            sourcePort: SourcePort,
            destinationPort: DestinationPort3);

        _sut = new TcpConnectionCounterAnalysis();
    }

    [Theory]
    //         UQ ES CL CN CC RN RC
    [InlineData(1, 0, 0, 0, 0, 0, 0, TcpConnectionState.Unknown)]
    [InlineData(1, 1, 0, 0, 0, 0, 0, TcpConnectionState.Established)]
    [InlineData(1, 1, 0, 0, 0, 0, 0, TcpConnectionState.AssumedEstablished)]
    [InlineData(1, 0, 1, 0, 0, 0, 0, TcpConnectionState.Closed)]
    [InlineData(1, 0, 0, 0, 0, 1, 0, TcpConnectionState.SynSent, PacketDirection.Incoming)]
    [InlineData(1, 0, 0, 1, 0, 0, 0, TcpConnectionState.SynSent, PacketDirection.Outgoing)]
    [InlineData(1, 0, 0, 0, 0, 0, 1, TcpConnectionState.FirstFinishSent, PacketDirection.Incoming)]
    [InlineData(1, 0, 0, 0, 1, 0, 0, TcpConnectionState.FirstFinishSent, PacketDirection.Outgoing)]
    public void Process_SingleConnectionSingleSnapshot(
        int uniqueConnectionCount,
        int establishedConnectionCount,
        int closedConnectionCount,
        int clientNewConnectionRequestCount,
        int clientCloseConnectionRequestCount,
        int remoteNewConnectionRequestCount,
        int remoteCloseConnectionRequestCount,
        TcpConnectionState tcpConnectionState,
        PacketDirection lastPacketDirection = PacketDirection.Outgoing)
    {
        // Arrange
        var capturedPacket = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);
        var tcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState,
            lastPacketDirection: lastPacketDirection,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var expectedTcpCounterMetrics = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount,
            EstablishedConnectionCount = establishedConnectionCount,
            ClosedConnectionCount = closedConnectionCount,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount,
        };

        // Act
        _sut.Process(capturedPacket, tcpConnectionSnapshot);

        // Assert
        _sut.TcpConnectionMetrics.Count.Should().Be(1);
        _sut.TcpConnectionMetrics[_transportLayerConnection1].Should().BeEquivalentTo(expectedTcpCounterMetrics);
        _sut.IpAggregatedMetrics.Count.Should().Be(1);
        _sut.IpAggregatedMetrics[_transportLayerConnection1.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics);
    }

    [Theory]
    //         UQ ES CL CN CC RN RC
    [InlineData(1, 2, 1, 0, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.Established)]
    [InlineData(2, 1, 1, 1, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.SynSent)]
    [InlineData(1, 0, 0, 3, 0, 0, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent)]
    [InlineData(1, 0, 0, 0, 3, 0, 0, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent)]
    [InlineData(1, 0, 0, 0, 0, 3, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent, PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming)]
    [InlineData(1, 0, 0, 0, 0, 0, 3, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming)]
    public void Process_SingleConnectionMultipleSnapshots(
        int uniqueConnectionCount,
        int establishedConnectionCount,
        int closedConnectionCount,
        int clientNewConnectionRequestCount,
        int clientCloseConnectionRequestCount,
        int remoteNewConnectionRequestCount,
        int remoteCloseConnectionRequestCount,
        TcpConnectionState tcpConnectionState1,
        TcpConnectionState tcpConnectionState2,
        TcpConnectionState tcpConnectionState3,
        PacketDirection lastPacketDirection1 = PacketDirection.Outgoing,
        PacketDirection lastPacketDirection2 = PacketDirection.Outgoing,
        PacketDirection lastPacketDirection3 = PacketDirection.Outgoing)
    {
        // Arrange
        var capturedPacket = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);

        var tcpConnectionSnapshot1 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState1,
            lastPacketDirection: lastPacketDirection1,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState2,
            lastPacketDirection: lastPacketDirection2,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot3 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState3,
            lastPacketDirection: lastPacketDirection3,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var expectedTcpCounterMetrics = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount,
            EstablishedConnectionCount = establishedConnectionCount,
            ClosedConnectionCount = closedConnectionCount,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount,
        };

        // Act
        _sut.Process(capturedPacket, tcpConnectionSnapshot1);
        _sut.Process(capturedPacket, tcpConnectionSnapshot2);
        _sut.Process(capturedPacket, tcpConnectionSnapshot3);

        // Assert
        _sut.TcpConnectionMetrics.Count.Should().Be(1);
        _sut.TcpConnectionMetrics[_transportLayerConnection1].Should().BeEquivalentTo(expectedTcpCounterMetrics);
        _sut.IpAggregatedMetrics.Count.Should().Be(1);
        _sut.IpAggregatedMetrics[_transportLayerConnection1.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics);
    }

    [Theory]
    //         UQ ES CL CN CC RN RC
    [InlineData(1, 0, 0, 0, 0, 0, 0, TcpConnectionState.Unknown, PacketDirection.Incoming,
                1, 1, 0, 0, 0, 0, 0, TcpConnectionState.Established, PacketDirection.Incoming,
                1, 1, 0, 0, 0, 0, 0, TcpConnectionState.AssumedEstablished, PacketDirection.Incoming)]
    [InlineData(1, 0, 1, 0, 0, 0, 0, TcpConnectionState.Closed, PacketDirection.Incoming,
                1, 0, 0, 0, 0, 1, 0, TcpConnectionState.SynSent, PacketDirection.Incoming,
                1, 0, 0, 1, 0, 0, 0, TcpConnectionState.SynSent, PacketDirection.Outgoing)]
    [InlineData(1, 0, 0, 0, 0, 0, 1, TcpConnectionState.FirstFinishSent, PacketDirection.Incoming,
                1, 0, 0, 0, 1, 0, 0, TcpConnectionState.FirstFinishSent, PacketDirection.Outgoing,
                1, 0, 0, 0, 0, 0, 0, TcpConnectionState.Unknown, PacketDirection.Outgoing)]
    public void Process_MultipleConnectionsSingleSnapshot(
        int uniqueConnectionCount1,
        int establishedConnectionCount1,
        int closedConnectionCount1,
        int clientNewConnectionRequestCount1,
        int clientCloseConnectionRequestCount1,
        int remoteNewConnectionRequestCount1,
        int remoteCloseConnectionRequestCount1,
        TcpConnectionState tcpConnectionState1,
        PacketDirection lastPacketDirection1,
        int uniqueConnectionCount2,
        int establishedConnectionCount2,
        int closedConnectionCount2,
        int clientNewConnectionRequestCount2,
        int clientCloseConnectionRequestCount2,
        int remoteNewConnectionRequestCount2,
        int remoteCloseConnectionRequestCount2,
        TcpConnectionState tcpConnectionState2,
        PacketDirection lastPacketDirection2,
        int uniqueConnectionCount3,
        int establishedConnectionCount3,
        int closedConnectionCount3,
        int clientNewConnectionRequestCount3,
        int clientCloseConnectionRequestCount3,
        int remoteNewConnectionRequestCount3,
        int remoteCloseConnectionRequestCount3,
        TcpConnectionState tcpConnectionState3,
        PacketDirection lastPacketDirection3)
    {
        // Arrange
        var capturedPacket1 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);
        var capturedPacket2 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress2);
        var capturedPacket3 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress3);

        var tcpConnectionSnapshot1 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState1,
            lastPacketDirection: lastPacketDirection1,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot2 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState2,
            lastPacketDirection: lastPacketDirection2,
            transportConnection: _transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot3 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState3,
            lastPacketDirection: lastPacketDirection3,
            transportConnection: _transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector);

        var expectedTcpCounterMetrics1 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount1,
            EstablishedConnectionCount = establishedConnectionCount1,
            ClosedConnectionCount = closedConnectionCount1,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount1,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount1,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount1,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount1,
        };

        var expectedTcpCounterMetrics2 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount2,
            EstablishedConnectionCount = establishedConnectionCount2,
            ClosedConnectionCount = closedConnectionCount2,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount2,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount2,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount2,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount2,
        };

        var expectedTcpCounterMetrics3 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount3,
            EstablishedConnectionCount = establishedConnectionCount3,
            ClosedConnectionCount = closedConnectionCount3,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount3,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount3,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount3,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount3,
        };

        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot1);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot2);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot3);

        // Assert
        _sut.TcpConnectionMetrics.Count.Should().Be(3);
        _sut.TcpConnectionMetrics[_transportLayerConnection1].Should().BeEquivalentTo(expectedTcpCounterMetrics1);
        _sut.TcpConnectionMetrics[_transportLayerConnection2].Should().BeEquivalentTo(expectedTcpCounterMetrics2);
        _sut.TcpConnectionMetrics[_transportLayerConnection3].Should().BeEquivalentTo(expectedTcpCounterMetrics3);
        _sut.IpAggregatedMetrics.Count.Should().Be(3);
        _sut.IpAggregatedMetrics[_transportLayerConnection1.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics1);
        _sut.IpAggregatedMetrics[_transportLayerConnection2.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics2);
        _sut.IpAggregatedMetrics[_transportLayerConnection3.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics3);
    }

    [Theory]
    //         UQ ES CL CN CC RN RC
    [InlineData(1, 2, 1, 0, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.Established,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                2, 1, 1, 1, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.SynSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                1, 0, 0, 3, 0, 0, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing)]
    [InlineData(1, 0, 0, 0, 3, 0, 0, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                1, 0, 0, 0, 0, 3, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent,
                                        PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming,
                1, 0, 0, 0, 0, 0, 3, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent,
                                        PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming)]
    public void Process_MultipleConnectionsMultipleSnapshots(
        int uniqueConnectionCount1,
        int establishedConnectionCount1,
        int closedConnectionCount1,
        int clientNewConnectionRequestCount1,
        int clientCloseConnectionRequestCount1,
        int remoteNewConnectionRequestCount1,
        int remoteCloseConnectionRequestCount1,
        TcpConnectionState tcpConnectionState11,
        TcpConnectionState tcpConnectionState12,
        TcpConnectionState tcpConnectionState13,
        PacketDirection lastPacketDirection11,
        PacketDirection lastPacketDirection12,
        PacketDirection lastPacketDirection13,
        int uniqueConnectionCount2,
        int establishedConnectionCount2,
        int closedConnectionCount2,
        int clientNewConnectionRequestCount2,
        int clientCloseConnectionRequestCount2,
        int remoteNewConnectionRequestCount2,
        int remoteCloseConnectionRequestCount2,
        TcpConnectionState tcpConnectionState21,
        TcpConnectionState tcpConnectionState22,
        TcpConnectionState tcpConnectionState23,
        PacketDirection lastPacketDirection21,
        PacketDirection lastPacketDirection22,
        PacketDirection lastPacketDirection23,
        int uniqueConnectionCount3,
        int establishedConnectionCount3,
        int closedConnectionCount3,
        int clientNewConnectionRequestCount3,
        int clientCloseConnectionRequestCount3,
        int remoteNewConnectionRequestCount3,
        int remoteCloseConnectionRequestCount3,
        TcpConnectionState tcpConnectionState31,
        TcpConnectionState tcpConnectionState32,
        TcpConnectionState tcpConnectionState33,
        PacketDirection lastPacketDirection31,
        PacketDirection lastPacketDirection32,
        PacketDirection lastPacketDirection33)
    {
        // Arrange
        var capturedPacket1 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);
        var capturedPacket2 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress2);
        var capturedPacket3 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress3);

        var tcpConnectionSnapshot11 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState11,
            lastPacketDirection: lastPacketDirection11,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot12 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState12,
            lastPacketDirection: lastPacketDirection12,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot13 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState13,
            lastPacketDirection: lastPacketDirection13,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot21 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState21,
            lastPacketDirection: lastPacketDirection21,
            transportConnection: _transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot22 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState22,
            lastPacketDirection: lastPacketDirection22,
            transportConnection: _transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot23 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState23,
            lastPacketDirection: lastPacketDirection23,
            transportConnection: _transportLayerConnection2,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot31 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState31,
            lastPacketDirection: lastPacketDirection31,
            transportConnection: _transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot32 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState32,
            lastPacketDirection: lastPacketDirection32,
            transportConnection: _transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot33 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState33,
            lastPacketDirection: lastPacketDirection33,
            transportConnection: _transportLayerConnection3,
            packetFlowDetector: _packetFlowDetector);

        var expectedTcpCounterMetrics1 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount1,
            EstablishedConnectionCount = establishedConnectionCount1,
            ClosedConnectionCount = closedConnectionCount1,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount1,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount1,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount1,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount1,
        };

        var expectedTcpCounterMetrics2 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount2,
            EstablishedConnectionCount = establishedConnectionCount2,
            ClosedConnectionCount = closedConnectionCount2,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount2,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount2,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount2,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount2,
        };

        var expectedTcpCounterMetrics3 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount3,
            EstablishedConnectionCount = establishedConnectionCount3,
            ClosedConnectionCount = closedConnectionCount3,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount3,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount3,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount3,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount3,
        };

        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot11);
        _sut.Process(capturedPacket1, tcpConnectionSnapshot12);
        _sut.Process(capturedPacket1, tcpConnectionSnapshot13);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot21);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot22);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot23);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot31);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot32);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot33);

        // Assert
        _sut.TcpConnectionMetrics.Count.Should().Be(3);
        _sut.TcpConnectionMetrics[_transportLayerConnection1].Should().BeEquivalentTo(expectedTcpCounterMetrics1);
        _sut.TcpConnectionMetrics[_transportLayerConnection2].Should().BeEquivalentTo(expectedTcpCounterMetrics2);
        _sut.TcpConnectionMetrics[_transportLayerConnection3].Should().BeEquivalentTo(expectedTcpCounterMetrics3);
        _sut.IpAggregatedMetrics.Count.Should().Be(3);
        _sut.IpAggregatedMetrics[_transportLayerConnection1.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics1);
        _sut.IpAggregatedMetrics[_transportLayerConnection2.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics2);
        _sut.IpAggregatedMetrics[_transportLayerConnection3.DestinationIpAddress].Should().BeEquivalentTo(expectedTcpCounterMetrics3);
    }

    [Theory]
    //         UQ ES CL CN CC RN RC
    [InlineData(1, 2, 1, 0, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.Established,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                2, 1, 1, 1, 0, 0, 0, TcpConnectionState.Established, TcpConnectionState.Closed, TcpConnectionState.SynSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                1, 0, 0, 3, 0, 0, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing)]
    [InlineData(1, 0, 0, 0, 3, 0, 0, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent,
                                        PacketDirection.Outgoing, PacketDirection.Outgoing, PacketDirection.Outgoing,
                1, 0, 0, 0, 0, 3, 0, TcpConnectionState.SynSent, TcpConnectionState.SynSent, TcpConnectionState.SynSent,
                                        PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming,
                1, 0, 0, 0, 0, 0, 3, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent, TcpConnectionState.FirstFinishSent,
                                        PacketDirection.Incoming, PacketDirection.Incoming, PacketDirection.Incoming)]
    public void Process_MultipleConnectionsMultipleSnapshotsMultiplePacketsForSameIPsAndDifferentPorts(
        int uniqueConnectionCount1,
        int establishedConnectionCount1,
        int closedConnectionCount1,
        int clientNewConnectionRequestCount1,
        int clientCloseConnectionRequestCount1,
        int remoteNewConnectionRequestCount1,
        int remoteCloseConnectionRequestCount1,
        TcpConnectionState tcpConnectionState11,
        TcpConnectionState tcpConnectionState12,
        TcpConnectionState tcpConnectionState13,
        PacketDirection lastPacketDirection11,
        PacketDirection lastPacketDirection12,
        PacketDirection lastPacketDirection13,
        int uniqueConnectionCount2,
        int establishedConnectionCount2,
        int closedConnectionCount2,
        int clientNewConnectionRequestCount2,
        int clientCloseConnectionRequestCount2,
        int remoteNewConnectionRequestCount2,
        int remoteCloseConnectionRequestCount2,
        TcpConnectionState tcpConnectionState21,
        TcpConnectionState tcpConnectionState22,
        TcpConnectionState tcpConnectionState23,
        PacketDirection lastPacketDirection21,
        PacketDirection lastPacketDirection22,
        PacketDirection lastPacketDirection23,
        int uniqueConnectionCount3,
        int establishedConnectionCount3,
        int closedConnectionCount3,
        int clientNewConnectionRequestCount3,
        int clientCloseConnectionRequestCount3,
        int remoteNewConnectionRequestCount3,
        int remoteCloseConnectionRequestCount3,
        TcpConnectionState tcpConnectionState31,
        TcpConnectionState tcpConnectionState32,
        TcpConnectionState tcpConnectionState33,
        PacketDirection lastPacketDirection31,
        PacketDirection lastPacketDirection32,
        PacketDirection lastPacketDirection33)
    {
        // Arrange
        var capturedPacket1 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);
        var capturedPacket2 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);
        var capturedPacket3 = CreateCapturedPacket(SourceIpAddress, DestinationIpAddress1);

        var tcpConnectionSnapshot11 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState11,
            lastPacketDirection: lastPacketDirection11,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot12 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState12,
            lastPacketDirection: lastPacketDirection12,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot13 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState13,
            lastPacketDirection: lastPacketDirection13,
            transportConnection: _transportLayerConnection1,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot21 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState21,
            lastPacketDirection: lastPacketDirection21,
            transportConnection: _transportLayerConnection12,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot22 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState22,
            lastPacketDirection: lastPacketDirection22,
            transportConnection: _transportLayerConnection12,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot23 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState23,
            lastPacketDirection: lastPacketDirection23,
            transportConnection: _transportLayerConnection12,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot31 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState31,
            lastPacketDirection: lastPacketDirection31,
            transportConnection: _transportLayerConnection13,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot32 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState32,
            lastPacketDirection: lastPacketDirection32,
            transportConnection: _transportLayerConnection13,
            packetFlowDetector: _packetFlowDetector);

        var tcpConnectionSnapshot33 = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            tcpConnectionState: tcpConnectionState33,
            lastPacketDirection: lastPacketDirection33,
            transportConnection: _transportLayerConnection13,
            packetFlowDetector: _packetFlowDetector);

        var expectedTcpCounterMetrics1 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount1,
            EstablishedConnectionCount = establishedConnectionCount1,
            ClosedConnectionCount = closedConnectionCount1,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount1,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount1,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount1,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount1,
        };

        var expectedTcpCounterMetrics2 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount2,
            EstablishedConnectionCount = establishedConnectionCount2,
            ClosedConnectionCount = closedConnectionCount2,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount2,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount2,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount2,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount2,
        };

        var expectedTcpCounterMetrics3 = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount3,
            EstablishedConnectionCount = establishedConnectionCount3,
            ClosedConnectionCount = closedConnectionCount3,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount3,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount3,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount3,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount3,
        };

        var expectedIpAggregatedMetrics = new TcpConnectionCounterMetrics
        {
            UniqueConnectionCount = uniqueConnectionCount1 + uniqueConnectionCount2 + uniqueConnectionCount3,
            EstablishedConnectionCount = establishedConnectionCount1 + establishedConnectionCount2 + establishedConnectionCount3,
            ClosedConnectionCount = closedConnectionCount2 + closedConnectionCount2 + closedConnectionCount3,
            ClientNewConnectionRequestCount = clientNewConnectionRequestCount1 + clientNewConnectionRequestCount2 + clientNewConnectionRequestCount3,
            ClientCloseConnectionRequestCount = clientCloseConnectionRequestCount1 + clientCloseConnectionRequestCount2 + clientCloseConnectionRequestCount3,
            RemoteNewConnectionRequestCount = remoteNewConnectionRequestCount1 + remoteNewConnectionRequestCount2 + remoteNewConnectionRequestCount3,
            RemoteCloseConnectionRequestCount = remoteCloseConnectionRequestCount1 + remoteCloseConnectionRequestCount2 + remoteCloseConnectionRequestCount3,
        };
        
        // Act
        _sut.Process(capturedPacket1, tcpConnectionSnapshot11);
        _sut.Process(capturedPacket1, tcpConnectionSnapshot12);
        _sut.Process(capturedPacket1, tcpConnectionSnapshot13);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot21);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot22);
        _sut.Process(capturedPacket2, tcpConnectionSnapshot23);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot31);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot32);
        _sut.Process(capturedPacket3, tcpConnectionSnapshot33);

        // Assert
        _sut.TcpConnectionMetrics.Count.Should().Be(3);
        _sut.TcpConnectionMetrics[_transportLayerConnection1].Should().BeEquivalentTo(expectedTcpCounterMetrics1);
        _sut.TcpConnectionMetrics[_transportLayerConnection12].Should().BeEquivalentTo(expectedTcpCounterMetrics2);
        _sut.TcpConnectionMetrics[_transportLayerConnection13].Should().BeEquivalentTo(expectedTcpCounterMetrics3);
        _sut.IpAggregatedMetrics.Count.Should().Be(1);
        _sut.IpAggregatedMetrics[_transportLayerConnection1.DestinationIpAddress].Should().BeEquivalentTo(expectedIpAggregatedMetrics);
    }

    private CapturedPacket CreateCapturedPacket(IPAddress sourceIp, IPAddress destinationIp)
    {
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: null,
            sourceIpAddress: sourceIp,
            destinationIpAddress: destinationIp);
        var capturedPacket = _packetFixtureFactory.CreateCapturedPacketFixture(
            networkPacket: ipPacket);
        return capturedPacket;
    }
}