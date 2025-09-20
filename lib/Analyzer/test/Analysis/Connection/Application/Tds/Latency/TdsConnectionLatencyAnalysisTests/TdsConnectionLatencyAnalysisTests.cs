// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Connection.Application.Tds.Latency.TdsConnectionLatencyAnalysisTests;

public partial class TdsConnectionLatencyAnalysisTests
{
    private const string SourceIpAddress = "192.168.1.1";
    private const int SourcePort = 1;
    private const int DestinationPort = 1;

    private const string DestinationIpAddress1 = "192.168.0.1";
    private const string DestinationIpAddress2 = "192.168.0.2";
    private const string DestinationIpAddress3 = "192.168.0.3";

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        IPAddress.Parse(SourceIpAddress)
    };

    private readonly TdsConnectionLatencyAnalysis _sut;

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly TransportLayerConnection _transportLayerConnection1;
    private readonly TransportLayerConnection _transportLayerConnection2;
    private readonly TransportLayerConnection _transportLayerConnection3;

    public TdsConnectionLatencyAnalysisTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _transportLayerConnection1 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress1),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _transportLayerConnection2 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress2),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _transportLayerConnection3 = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress3),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _sut = new TdsConnectionLatencyAnalysis();
    }

    private TdsConnectionSnapshot GetTdsConnectionSnapshot(
        TdsConnectionState tdsConnectionState = TdsConnectionState.Unknown,
        TcpConnectionState tcpConnectionState = TcpConnectionState.Established,
        TransportLayerConnection? transportLayerConnection = null,
        DateTime? firstSynTimestamp = null,
        DateTime? establishedTimestamp = null)
    {
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture();
        var tcpConnectionSnapshot = _snapshotFixtureFactory.CreateTcpConnectionSnapshotFixture(
            transportConnection: transportLayerConnection ?? _transportLayerConnection1,
            tcpConnectionState: tcpConnectionState,
            firstSynTimestamp: firstSynTimestamp,
            establishedTimestamp: establishedTimestamp);

        var tdsConnectionSnapshot = _snapshotFixtureFactory.CreateTdsConnectionSnapshotFixture(
            tcpSegment: tcpSegment,
            tcpConnectionSnapshot: tcpConnectionSnapshot,
            tdsConnectionState: tdsConnectionState);

        return tdsConnectionSnapshot;
    }

    private PacketData GetPacketData(
        DateTime timestamp,
        TdsConnectionState tdsConnectionState,
        TransportLayerConnection? transportLayerConnection = null,
        TcpConnectionState tcpConnectionState = TcpConnectionState.Established,
        DateTime? firstSynTimestamp = null,
        DateTime? establishedTimestamp = null)
    {
        return new PacketData
        {
            Packet = _packetFixtureFactory.CreateCapturedPacketFixture(capturedDateTime: timestamp),
            Snapshot = GetTdsConnectionSnapshot(
                tdsConnectionState: tdsConnectionState,
                tcpConnectionState: tcpConnectionState,
                transportLayerConnection: transportLayerConnection,
                firstSynTimestamp: firstSynTimestamp,
                establishedTimestamp: establishedTimestamp),
        };
    }

    private class TransportConnectionSnapshotFake : TcpConnectionSnapshot
    {
        public TransportConnectionSnapshotFake(
            IpPacket ipPacket,
            TcpSegment tcpSegment,
            TransportLayerConnection transportConnection,
            IPacketFlowDetector packetFlowDetector)
            : base(ipPacket, tcpSegment, transportConnection, packetFlowDetector)
        {
        }
    }

    private class PacketData
    {
        public required CapturedPacket Packet { get; set; }

        public required TdsConnectionSnapshot Snapshot { get; set; }
    }
}