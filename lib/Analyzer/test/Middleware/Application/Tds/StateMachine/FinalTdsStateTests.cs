// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds.StateMachine.States;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Application.Tds.StateMachine;

public class FinalTdsStateTests
{
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly FinalTdsStateMock _sut;

    private const int SourcePort = 80;
    private const int DestinationPort = 1433;

    private static readonly IPAddress _ipv4Address = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _referenceIpAddress = IPAddress.Parse("192.0.0.9");

    public FinalTdsStateTests()
    {
        _packetFixtureFactory = new PacketFixtureFactory();

        _packetFlowDetector = new ReferenceIpPacketFlowDetector(new []{ _referenceIpAddress });

        _sut = new FinalTdsStateMock(_packetFlowDetector);
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
        nextState.TdsConnectionState.Should().Be(TdsConnectionState.TcpHandshake);
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
        nextState.Should().BeEquivalentTo(expectedState);
    }

    internal class FinalTdsStateMock : FinalTdsState
    {
        /// <inheritdoc />
        public FinalTdsStateMock(IPacketFlowDetector packetFlowDetector)
            : base(packetFlowDetector)
        {
        }

        /// <inheritdoc />
        internal override TdsConnectionState TdsConnectionState => TdsConnectionState.Unknown;
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