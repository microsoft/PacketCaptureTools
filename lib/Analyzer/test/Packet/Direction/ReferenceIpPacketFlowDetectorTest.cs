// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Direction
{
    public class ReferenceIpPacketFlowDetectorTest
    {
        private static readonly IPAddress _ipv4Address1 = IPAddress.Parse("192.0.1.1");
        private static readonly IPAddress _ipv4Address2 = IPAddress.Parse("192.0.1.2");

        private static readonly IPAddress _ipv6Address1 = IPAddress.Parse("0:0:0:0:0:0:0:1");

        private static readonly IPAddress _referenceIpAddress1 = IPAddress.Parse("192.0.0.9");
        private static readonly IPAddress _referenceIpAddress2 = IPAddress.Parse("0:0:0:0:0:0:0:9");

        private static readonly HashSet<IPAddress> _referenceIpAddresses = [
            _referenceIpAddress1,
            _referenceIpAddress2,
        ];

        private readonly PacketFixtureFactory _packetFixtureFactory;
        private readonly ReferenceIpPacketFlowDetector _sut;

        public ReferenceIpPacketFlowDetectorTest()
        {
            _packetFixtureFactory = new PacketFixtureFactory();
            _sut = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        }

        [Fact]
        public void Constructor_ReferenceIpAddressParameterNull_ReturnsArgumentException()
        {
            // Arrange
            // Act
            Action sut = () => { _ = new ReferenceIpPacketFlowDetector(null!); };

            // Assert
            sut.Should().Throw<ArgumentException>().WithMessage("Reference Ip Addresses cannot be null or empty. (Parameter 'referenceIpAddresses')");
        }

        [Fact]
        public void Constructor_ReferenceIpAddressParameterEmpty_ReturnsArgumentException()
        {
            // Arrange
            // Act
            Action sut = () => { _ = new ReferenceIpPacketFlowDetector(new HashSet<IPAddress> { }); };

            // Assert
            sut.Should().Throw<ArgumentException>().WithMessage("Reference Ip Addresses cannot be null or empty. (Parameter 'referenceIpAddresses')");
        }

        [Fact]
        public void Constructor_ValidParameters_ExpectedValues()
        {
            // Arrange
            var expectedReferenceIpAddresses = new HashSet<IPAddress>
            {
                IPAddress.Parse("192.0.0.9"),
                IPAddress.Parse("0:0:0:0:0:0:0:9"),
            };

            // Act
            var sut = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);

            // Assert
            sut.ReferenceIpAddresses.Should().HaveCount(2);
            sut.ReferenceIpAddresses.Should().Equal(expectedReferenceIpAddresses);
        }

        [Fact]
        public void GetCapturedPacketDirection_NullPacket_ThrowsArgumentNullException()
        {
            // Arrange
            // Act
            Action result = () => { _sut.GetCapturedPacketDirection(null!); };

            // Assert
            result.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void GetNetworkPacketDirection_NullPacket_ThrowsArgumentNullException()
        {
            // Arrange
            // Act
            Action result = () => { _sut.GetNetworkPacketDirection(null!); };

            // Assert
            result.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void GetCapturedPacketDirection_NoSourceNoDestinationInReferenceIpSet_IsIncoming()
        {
            // Arrange
            var packet = CreateCapturedPacket(_ipv4Address1, _ipv4Address2);

            // Act
            var result = _sut.GetCapturedPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Unknown);
        }

        [Fact]
        public void GetNetworkPacketDirection_NoSourceNoDestinationInReferenceIpSet_IsIncoming()
        {
            // Arrange
            var packet = CreateNetworkPacket(_ipv4Address1, _ipv4Address2);

            // Act
            var result = _sut.GetNetworkPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Unknown);
        }

        [Fact]
        public void GetCapturedPacketDirection_NoSourceInReferenceIpSet_IsIncoming()
        {
            // Arrange
            var packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1);

            // Act
            var result = _sut.GetCapturedPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Incoming);
            result.Should().NotBe(PacketDirection.Outgoing);
        }

        [Fact]
        public void GetNetworkPacketDirection_NoSourceInReferenceIpSet_IsIncoming()
        {
            // Arrange
            var packet = CreateNetworkPacket(_ipv4Address1, _referenceIpAddress1);

            // Act
            var result = _sut.GetNetworkPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Incoming);
            result.Should().NotBe(PacketDirection.Outgoing);
        }

        [Fact]
        public void GetCapturedPacketDirection_NoDestinationInReferenceIpSet_IsOutgoing()
        {
            // Arrange
            var packet = CreateCapturedPacket(_referenceIpAddress2, _ipv6Address1);

            // Act
            var result = _sut.GetCapturedPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Outgoing);
            result.Should().NotBe(PacketDirection.Incoming);
        }

        [Fact]
        public void GetNetworkPacketDirection_NoDestinationInReferenceIpSet_IsOutgoing()
        {
            // Arrange
            var packet = CreateNetworkPacket(_referenceIpAddress2, _ipv6Address1);

            // Act
            var result = _sut.GetNetworkPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Outgoing);
            result.Should().NotBe(PacketDirection.Incoming);
        }

        [Fact]
        public void GetCapturedPacketDirection_BothSourceAndDestinationInReferenceIps_IsOutgoing()
        {
            // Arrange
            var packet = CreateCapturedPacket(_referenceIpAddress1, _referenceIpAddress2);

            // Act
            var result = _sut.GetCapturedPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Outgoing);
            result.Should().NotBe(PacketDirection.Incoming);
        }

        [Fact]
        public void GetNetworkPacketDirection_BothSourceAndDestinationInReferenceIps_IsOutgoing()
        {
            // Arrange
            var packet = CreateNetworkPacket(_referenceIpAddress1, _referenceIpAddress2);

            // Act
            var result = _sut.GetNetworkPacketDirection(packet);

            // Assert
            result.Should().Be(PacketDirection.Outgoing);
            result.Should().NotBe(PacketDirection.Incoming);
        }

        private CapturedPacket CreateCapturedPacket(
            IPAddress sourceIpAddress,
            IPAddress destinationIpAddress)
        {
            TransportSegment transportSegment = _packetFixtureFactory.CreateTcpSegmentFixture();
            NetworkPacket networkPacket = CreateNetworkPacket(sourceIpAddress, destinationIpAddress, transportSegment);

            var ethernetFrame = _packetFixtureFactory.CreateEthernetFrameFixture(networkPacket);
            var packet = _packetFixtureFactory.CreateCapturedPacketFixture(
                physicalFrame: ethernetFrame,
                networkPacket: networkPacket,
                transportSegment: transportSegment);
            return packet;
        }

        private NetworkPacket CreateNetworkPacket(
            IPAddress sourceIpAddress,
            IPAddress destinationIpAddress,
            TransportSegment? transportSegment = null)
        {
            transportSegment ??= _packetFixtureFactory.CreateTcpSegmentFixture();

            NetworkPacket networkPacket;

            if (sourceIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                networkPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
                    transportSegment,
                    sourceIpAddress: sourceIpAddress,
                    destinationIpAddress: destinationIpAddress);
            }
            else if (sourceIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                networkPacket = _packetFixtureFactory.CreateIPv6PacketFixture(
                    transportSegment,
                    sourceIpAddress: sourceIpAddress,
                    destinationIpAddress: destinationIpAddress);
            }
            else
            {
                throw new Exception("Only IPv4 and IPv6 are supported.");
            }

            return networkPacket;
        }
    }
}
