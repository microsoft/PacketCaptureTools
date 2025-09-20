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

public class TcpHandshakeStateTests
{
    private const int SourcePort = 80;
    private const int DestinationPort = 1433;

    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TdsState _sut;

    public TcpHandshakeStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new TcpHandshakeTdsState(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_ValidParams_Succeeds()
    {
        // Arrange
        // Act
        Action action = () => new TcpHandshakeTdsState(_packetFlowDetector);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action action = () => new TcpHandshakeTdsState(null!);

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
    public void GetNextTdsState_IncomingTcpDataSegmentPshFlag_ReturnsPreLoginState()
    {
        // Arrange
        var expectedState = new PreLoginTdsState(_packetFlowDetector);
        var tcpSegment = CreateTcpSegment(new TcpFlags(psh: true));
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTcpDataSegmentPshFlag_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;
        var tcpSegment = CreateTcpSegment(new TcpFlags(psh: true));
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, null, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTcpDataSegmentNoPshFlag_ReturnsOriginalState()
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
    public void GetNextTdsState_OutgoingTcpDataSegmentNoPshFlag_ReturnsOriginalState()
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
    public void GetNextTdsState_IncomingTdsMessagePreLoginNullTls_ReturnsPreLoginState()
    {
        // Arrange
        var expectedState = new PreLoginTdsState(_packetFlowDetector);

        var tdsMessage = CreateTdsMessage(TdsMessageType.PreLogin);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTdsMessagePreLogin_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.PreLogin);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTdsMessagePreLoginNotNullTls_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.PreLogin);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTdsMessageNotPreLogin_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.Rpc);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_OutgoingTdsMessageNotPreLogin_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.Rpc);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState);
    }

    [Fact]
    public void GetNextTdsState_IncomingTlsRecord_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        var tcpSegment = CreateTcpSegment(new TcpFlags(), tlsRecord.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

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
        IPAddress sourceAddress,
        IPAddress destinationAddress)
    {
        var ipPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
            transportSegment: tcpSegment,
            sourceIpAddress: sourceAddress,
            destinationIpAddress: destinationAddress);

        return ipPacket;
    }

    private TdsMessage CreateTdsMessage(TdsMessageType messageType)
    {
        var tdsMessage = new TdsMessage(
            messageType: messageType,
            status: Status.EndOfMessage,
            length: 1,
            channel: 0,
            packetNumber: 1,
            window: 1,
            payload: new byte[] { });

        return tdsMessage;
    }
}