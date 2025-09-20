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

public class LoginAckStateTests
{
    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private const int SourcePort = 80;
    private const int DestinationPort = 1433;

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TdsState _sut;

    public LoginAckStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new LoginAckTdsState(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_ValidParams_Succeeds()
    {
        // Arrange
        // Act
        Action action = () => new LoginAckTdsState(_packetFlowDetector);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action action = () => new LoginAckTdsState(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void GetNextTdsState_InvalidParams_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        // Act
        var nextState = _sut.GetNextTdsState(null, null, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegment_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags());

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _referenceIpAddress,
            destinationIpAddress: _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
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
    public void GetNextTdsState_IncomingTdsMessageWithoutAnyFlags_ReturnsSameState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = new TdsMessage(
            messageType: TdsMessageType.Tds7Login,
            status: Status.EndOfMessage,
            length: 10,
            channel: 0,
            packetNumber: 100,
            window: 100,
            payload: new byte[] { });

        var tcpSegment = CreateTcpSegment(new TcpFlags(), tdsMessage.ConvertToBytes());
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

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags(),
            payload: tlsRecord.ConvertToBytes());

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _referenceIpAddress,
            destinationIpAddress: _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_FinFlagSet_ReturnsClosedWithSuccessTdsState()
    {
        // Arrange
        var expectedState = new ConnectionClosedAfterLoginAckTdsState(_packetFlowDetector);

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags(fin: true),
            payload: tlsRecord.ConvertToBytes());

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _referenceIpAddress,
            destinationIpAddress: _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_RstFlagSet_ReturnsClosedWithSuccessTdsState()
    {
        // Arrange
        var expectedState = new ConnectionClosedAfterLoginAckTdsState(_packetFlowDetector);

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        var tcpSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: 80,
            destinationPort: 1433,
            tcpFlags: new TcpFlags(rst: true),
            payload: tlsRecord.ConvertToBytes());

        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: _referenceIpAddress,
            destinationIpAddress: _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
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
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: packetDirection == PacketDirection.Incoming ? _ipv4Address : _referenceIpAddress,
            destinationIpAddress: packetDirection == PacketDirection.Incoming ? _referenceIpAddress : _ipv4Address);

        return ipPacket;
    }
}