// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Application.Tds.StateMachine.States;

public class ConnectionClosedWithErrorTdsStateTests
{
    private const int SourcePort = 80;
    private const int DestinationPort = 1433;

    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress>
    {
        _referenceIpAddress,
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TdsState _sut;

    public ConnectionClosedWithErrorTdsStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new ConnectionClosedWithErrorTdsState(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_ValidParams_Succeeds()
    {
        // Arrange
        // Act
        Action action = () => new ConnectionClosedWithErrorTdsState(_packetFlowDetector);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action action = () => new ConnectionClosedWithErrorTdsState(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void GetNextTdsState_InvalidParams_ReturnsOriginalState()
    {
        // Arrange
        // Act
        var nextState = _sut.GetNextTdsState(null, null, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(_sut);
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentFinFlag_ReturnsConnectionClosedState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(fin: true));
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentFinFlag_ReturnsConnectionClosedState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(fin: true));
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentRstFlag_ReturnsConnectionClosedState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(rst: true));
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentRstFlag_ReturnsConnectionClosedState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(rst: true));
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentNoFlags_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment();
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentNoFlags_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment();
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }
    
    [Fact]
    public void GetNextTdsState_IncomingTdsMessageWithSynFlag_ReturnsTcpHandshakeState()
    {
        // Arrange
        var expectedState = new TcpHandshakeTdsState(_packetFlowDetector);

        var tdsMessage = new TdsMessage(
            messageType: TdsMessageType.Tds7Login,
            status: Status.EndOfMessage,
            length: 10,
            channel: 0,
            packetNumber: 100,
            window: 100,
            payload: new byte[] { });

        var tcpSegment = CreateTcpSegment(new TcpFlags(syn: true), tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, PacketDirection.Incoming);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTlsRecord_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        var tcpSegment = CreateTcpSegment(new TcpFlags(psh: true), tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    private TcpSegment CreateTcpSegment(
        TcpFlags? tcpFlags = null,
        byte[]? payload = null,
        uint payloadSize = 0,
        int sourcePort = SourcePort,
        int destinationPort = DestinationPort)
    {
        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            tcpFlags: tcpFlags,
            payload: payload,
            payloadSize: payloadSize);

        return tcpSegment;
    }

    private IpPacket CreateIpPacket(
        TcpSegment tcpSegment,
        PacketDirection packetDirection)
    {
        var ipPacket = CreateIpPacket(
            tcpSegment: tcpSegment,
            sourceAddress: packetDirection == PacketDirection.Incoming ? _ipv4Address : _referenceIpAddress,
            destinationAddress: packetDirection == PacketDirection.Incoming ? _referenceIpAddress : _ipv4Address);

        return ipPacket;
    }

    private IpPacket CreateIpPacket(
        TcpSegment tcpSegment,
        IPAddress sourceAddress,
        IPAddress destinationAddress)
    {
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: sourceAddress,
            destinationIpAddress: destinationAddress);

        return ipPacket;
    }
}