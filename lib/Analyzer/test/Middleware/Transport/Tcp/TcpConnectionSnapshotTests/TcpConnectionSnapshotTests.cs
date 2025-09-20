// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using System.Reflection;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport.Tcp.TcpConnectionSnapshotTests;

public partial class TcpConnectionSnapshotTests
{
    private const string SourceIpAddress = "192.168.0.1";
    private const int SourcePort = 1;

    private const string DestinationIpAddress = "192.168.0.2";
    private const int DestinationPort = 2;

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        IPAddress.Parse(SourceIpAddress)
    };

    private const uint LastSeenSequenceNumber = 100;
    private const uint LastSeenAcknowledgementNumber = 101;

    private const int IpHeaderTotalLength = 50;
    private const int IpHeaderHeaderLengthInWords = 10;
    private const int TcpSegmentDataOffset = 20;
    private const int TcpSegmentPayloadSize = IpHeaderTotalLength - TcpSegmentDataOffset;
    private readonly TransportLayerConnection _transportLayerConnection;
    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly SnapshotFixtureFactory _snapshotFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;

    private readonly DateTime _packetCaptureTimestamp = DateTime.UtcNow;

    private readonly TcpSegment _tcpSegment;
    private readonly IpPacket _ipPacket;

    public TcpConnectionSnapshotTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _snapshotFixtureFactory = new SnapshotFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

        _transportLayerConnection = new TransportLayerConnection(
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress),
            sourcePort: SourcePort,
            destinationPort: DestinationPort);

        _tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: _transportLayerConnection.SourcePort,
            destinationPort: _transportLayerConnection.DestinationPort,
            sequenceNumber: LastSeenSequenceNumber,
            acknowledgementNumber: LastSeenAcknowledgementNumber,
            tcpFlags: new TcpFlags(ack: true));

        _ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: _tcpSegment,
            sourceIpAddress: IPAddress.Parse(SourceIpAddress),
            destinationIpAddress: IPAddress.Parse(DestinationIpAddress));
    }

    private TcpConnectionSnapshot GetTcpConnectionSnapshotFixture(
        PacketDirection packetDirection,
        uint sequenceNumber = LastSeenSequenceNumber,
        uint acknowledgementNumber = LastSeenAcknowledgementNumber,
        uint tcpSegmentDataOffset = TcpSegmentDataOffset,
        uint tcpSegmentPayloadSize = TcpSegmentPayloadSize,
        int ipHeaderTotalLength = IpHeaderTotalLength,
        int ipHeaderHeaderLengthInWords = IpHeaderHeaderLengthInWords)
    {
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: packetDirection == PacketDirection.Outgoing ? _transportLayerConnection.SourcePort : _transportLayerConnection.DestinationPort,
            destinationPort: packetDirection == PacketDirection.Outgoing ? _transportLayerConnection.DestinationPort : _transportLayerConnection.SourcePort,
            sequenceNumber: sequenceNumber,
            acknowledgementNumber: acknowledgementNumber,
            tcpFlags: new TcpFlags(syn: true),
            dataOffset: tcpSegmentDataOffset,
            payloadSize: tcpSegmentPayloadSize);

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: IPAddress.Parse(packetDirection == PacketDirection.Outgoing ? SourceIpAddress : DestinationIpAddress),
            destinationIpAddress: IPAddress.Parse(packetDirection == PacketDirection.Outgoing ? DestinationIpAddress : SourceIpAddress),
            totalLength: ipHeaderTotalLength,
            headerLengthInWords: ipHeaderHeaderLengthInWords);

        return new TcpConnectionSnapshot(
            ipPacket: ipPacket,
            tcpSegment: tcpSegment,
            transportConnection: _transportLayerConnection,
            packetFlowDetector: _packetFlowDetector,
            packetCaptureTimestamp: _packetCaptureTimestamp);
    }

    private MethodInfo? GetMethodInfo(string methodName)
    {
        return typeof(TcpConnectionSnapshot).GetMethod(
            name: methodName,
            bindingAttr: BindingFlags.NonPublic | BindingFlags.Instance);
    }

    private MethodInfo? GetMethodInfo(string methodName, Type[] types)
    {
        return typeof(TcpConnectionSnapshot).GetMethod(
            name: methodName,
            bindingAttr: BindingFlags.NonPublic | BindingFlags.Instance,
            types: types,
            callConvention: CallingConventions.Standard,
            binder: null,
            modifiers: null);
    }
}