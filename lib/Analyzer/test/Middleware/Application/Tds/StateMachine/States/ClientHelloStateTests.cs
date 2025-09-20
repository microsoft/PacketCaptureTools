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

public class ClientHelloStateTests
{
    private const int SourcePort = 80;
    private const int DestinationPort = 1433;
    private const int TlsVersion = 0x3030;
    private const int TlsLength = 100;

    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TdsState _sut;

    public ClientHelloStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new ClientHelloTdsState(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_ValidParams_Succeeds()
    {
        // Arrange
        // Act
        Action action = () => new ClientHelloTdsState(_packetFlowDetector);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action action = () => new ClientHelloTdsState(null!);

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
    public void GetNextTdsState_IncomingTcpDataSegmentPshFlag_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(psh: true));
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentPshFlag_ReturnsServerHelloState()
    {
        // Arrange
        var expectedState = new ServerHelloTdsState(_packetFlowDetector);

        var tcpSegment = CreateTcpSegment(new TcpFlags(psh: true));
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentAckFlagNonZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(ack: true), new byte[1], 1);
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentAckFlagNonZeroPayload_ReturnsServerHelloState()
    {
        // Arrange
        var expectedState = new ServerHelloTdsState(_packetFlowDetector);

        var tcpSegment = CreateTcpSegment(new TcpFlags(ack: true), new byte[1], 1);
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentNoFlagsNonZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(), new byte[1], 1);
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentNoFlagsNonZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(), new byte[1], 1);
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentAckFlagZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(ack: true), new byte[0], 0);
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentAckFlagZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(ack: true), new byte[0], 0);
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentNoFlagsZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(), new byte[0], 0);
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentNoFlagsZeroPayload_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tcpSegment = CreateTcpSegment(new TcpFlags(), new byte[0], 0);
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_TdsMessage_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = new TdsMessage(
            messageType: TdsMessageType.PreLogin,
            status: Status.EndOfMessage,
            length: 10,
            channel: 0,
            packetNumber: 100,
            window: 100,
            payload: new byte[] { });

        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTlsHandshakeServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Handshake, MessageType.ServerHello);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTlsHandshakeServerHello_ReturnsServerHelloState()
    {
        // Arrange
        var expectedState = new ServerHelloTdsState(_packetFlowDetector);

        var tlsRecord = CreateTlsRecord(ContentType.Handshake, MessageType.ServerHello);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTlsHandshakeNotServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Handshake);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTlsHandshakeNotServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Handshake);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTlsNotHandshakeServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Application, MessageType.ServerHello);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTlsNotHandshakeServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Application, MessageType.ServerHello);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTlsNotHandshakeNotServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Application);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTlsNotHandshakeNotServerHello_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = CreateTlsRecord(ContentType.Application);
        var tcpSegment = CreateTcpSegment(payload: tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

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
        IPAddress sourceAddress,
        IPAddress destinationAddress)
    {
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: sourceAddress,
            destinationIpAddress: destinationAddress);

        return ipPacket;
    }

    private TlsRecord CreateTlsRecord(
        ContentType contentType,
        MessageType messageType = MessageType.Unknown,
        int version = TlsVersion,
        int length = TlsLength)
    {
        var tlsRecord = new TlsRecord(
            contentType: contentType,
            version: version,
            length: length,
            messageType: messageType);

        return tlsRecord;
    }
}