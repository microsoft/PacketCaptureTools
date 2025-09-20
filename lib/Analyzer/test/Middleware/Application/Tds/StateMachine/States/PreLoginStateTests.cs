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

public class PreLoginStateTests
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

    public PreLoginStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new PreLoginTdsState(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_ValidParams_Succeeds()
    {
        // Arrange
        // Act
        Action action = () => new PreLoginTdsState(_packetFlowDetector);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action action = () => new PreLoginTdsState(null!);

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
    public void GetNextTdsState_OutgoingTcpDataSegmentPshFlag_ReturnsPreLoginResponseState()
    {
        // Arrange
        var expectedState = new PreLoginResponseTdsState(_packetFlowDetector);

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
    public void GetNextTdsState_OutgoingTcpDataSegmentAckFlagNonZeroPayload_ReturnsPreLoginResponseState()
    {
        // Arrange
        var expectedState = new PreLoginResponseTdsState(_packetFlowDetector);

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
    public void GetNextTdsState_IncomingTdsMessageServerResponse_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.ServerResponse);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTdsMessageServerResponseNullTls_ReturnsPreLoginResponseState()
    {
        // Arrange
        var expectedState = new PreLoginResponseTdsState(_packetFlowDetector);

        var tdsMessage = CreateTdsMessage(TdsMessageType.ServerResponse);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTdsMessageServerResponseNotNullTls_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.ServerResponse);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

        var tlsRecord = new TlsRecord(
            contentType: ContentType.ChangeCipherSpec,
            version: 0x3030,
            length: 100,
            messageType: MessageType.Unknown);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, tlsRecord);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_IncomingTdsMessageNotServerResponse_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.Rpc);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _ipv4Address, _referenceIpAddress);

        // Act
        var nextState = _sut.GetNextTdsState(ipPacket, tcpSegment, tdsMessage, null);

        // Assert
        nextState.Should().BeEquivalentTo(expectedState, options => options.IncludingInternalProperties());
    }

    [Fact]
    public void GetNextTdsState_OutgoingTdsMessageNotServerResponse_ReturnsOriginalState()
    {
        // Arrange
        var expectedState = _sut;

        var tdsMessage = CreateTdsMessage(TdsMessageType.Rpc);
        var tcpSegment = CreateTcpSegment(payload: tdsMessage.ConvertToBytes());
        var ipPacket = CreateIpPacket(tcpSegment, _referenceIpAddress, _ipv4Address);

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

        var tcpSegment = CreateTcpSegment(new TcpFlags(), tlsRecord.ConvertToBytes());
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