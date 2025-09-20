// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Packet;

public class TcpPacketResetAnalysisTest
{
    private static readonly DateTime _time = DateTime.UtcNow;
    private static readonly DateTime _timeTruncatedToSeconds = DateTime.UtcNow.TruncateToSeconds();

    private static readonly IPAddress _ipv4Address1 = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _ipv6Address1 = IPAddress.Parse("0:0:0:0:0:0:0:1");

    private static readonly IPAddress _referenceIpAddress1 = IPAddress.Parse("192.0.0.9");
    private static readonly IPAddress _referenceIpAddress2 = IPAddress.Parse("0:0:0:0:0:0:0:9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress1,
        _referenceIpAddress2,
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TcpPacketResetAnalysis _sut;

    public TcpPacketResetAnalysisTest()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new TcpPacketResetAnalysis(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_NullPacketFlowDetector_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action sut = () => { new TcpPacketResetAnalysis(null!); };

        // Assert
        sut.Should().Throw<ArgumentNullException>();

    }

    [Fact]
    public void Constructor_ValidParameters_ExpectedValues()
    {
        // Arrange
        var expectedCountByConnection = new Dictionary<(IPAddress, IPAddress, int, int), int>();
        var expectedPerIpResetCount = new Dictionary<IPAddress, (int asSource, int asDestination)>();
        var expectedCountBySecond = new Dictionary<DateTime, int>();

        // Act
        var sut = new TcpPacketResetAnalysis(_packetFlowDetector);

        // Assert
        sut.Should().NotBeNull();
        _sut.GlobalCount.Should().Be(0);
        _sut.CountByConnection.Should().Equal(expectedCountByConnection);
        _sut.PerIpResetCount.Should().Equal(expectedPerIpResetCount);
        _sut.CountBySecond.Should().Equal(expectedCountBySecond);

    }

    [Fact]
    public void Process_ZeroPacketsProcessed_CountersEqualToDefaultValues()
    {
        // Arrange
        var expectedCountByConnection = new Dictionary<(IPAddress, IPAddress, int, int), int>();
        var expectedPerIpResetCount = new Dictionary<IPAddress, (int asSource, int asDestination)>();
        var expectedCountBySecond = new Dictionary<DateTime, int>();

        // Act
        _sut.Process(null!);

        // Assert
        _sut.GlobalCount.Should().Be(0);
        _sut.CountByConnection.Should().Equal(expectedCountByConnection);
        _sut.PerIpResetCount.Should().Equal(expectedPerIpResetCount);
        _sut.CountBySecond.Should().Equal(expectedCountBySecond);
    }

    [Fact]
    public void Process_SingleTcpResetPacket_CountersEqualOneForOneConnection()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time);

        var expectedCountByConnection = new Dictionary<(IPAddress, IPAddress, int, int), int>
        {
            {
                (_ipv4Address1, _referenceIpAddress1, 0, 0), 1
            }
        };

        var expectedPerIpResetCount = new Dictionary<IPAddress, (int asSource, int asDestination)>
        {
            {
                _ipv4Address1, (1, 0)
            }
        };

        var expectedCountBySecond = new Dictionary<DateTime, int>
        {
            {
                _timeTruncatedToSeconds, 1
            }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, packet.TransportSegment!);

        // Assert
        _sut.GlobalCount.Should().Be(1);
        _sut.CountByConnection.Should().Equal(expectedCountByConnection);
        _sut.PerIpResetCount.Should().Equal(expectedPerIpResetCount);
        _sut.CountBySecond.Should().Equal(expectedCountBySecond);
    }

    [Fact]
    public void Process_ThreeTcpResetPacketsFromSameConnection_CountersEqualThreeForOneConnection()
    {
        // Arrange
        var capturedPackets = new List<CapturedPacket>
        {
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
        };

        var expectedCountByConnection = new Dictionary<(IPAddress, IPAddress, int, int), int> 
        {
            {
                (_ipv4Address1, _referenceIpAddress1, 0, 0), 3
            }
        };

        var expectedPerIpResetCount = new Dictionary<IPAddress, (int asSource, int asDestination)>
        {
            {
                _ipv4Address1, (3, 0)
            }
        };

        var expectedCountBySecond = new Dictionary<DateTime, int>
        {
            {
                _timeTruncatedToSeconds, 3
            }
        };

        // Act
        foreach(var packet in capturedPackets)
        {
            _sut.Process(packet, (IpPacket)packet.NetworkPacket!, packet.TransportSegment!);
        }

        // Assert
        _sut.GlobalCount.Should().Be(3);
        _sut.CountByConnection[(_ipv4Address1, _referenceIpAddress1, 0, 0)].Should().Be(3);
        _sut.CountByConnection.Should().Equal(expectedCountByConnection);
        _sut.PerIpResetCount.Should().Equal(expectedPerIpResetCount);
        _sut.CountBySecond.Should().Equal(expectedCountBySecond);
    }

    [Fact]
    public void Process_ThreeTcpResetPacketsFromTwoDifferentConnectionsEach_CountersEqualThreeForBothConnections()
    {
        // Arrange
        var capturedPackets = new List<CapturedPacket>
        {
            // connection 1
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, true, _time),
            // connection 2
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address1, true, _time),
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address1, true, _time),
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address1, true, _time),
        };

        var expectedCountByConnection = new Dictionary<(IPAddress, IPAddress, int, int), int>
        {
            {
                (_ipv4Address1, _referenceIpAddress1, 0, 0), 3
            },
            {
                (_referenceIpAddress2, _ipv6Address1, 0, 0), 3
            }
        };

        var expectedPerIpResetCount = new Dictionary<IPAddress, (int asSource, int asDestination)>
        {
            {
                _ipv4Address1, (3, 0)
            },
            {
                _ipv6Address1, (0, 3)
            }
        };

        var expectedCountBySecond = new Dictionary<DateTime, int>
        {
            {
                _timeTruncatedToSeconds, 6
            }
        };

        // Act
        foreach (var packet in capturedPackets)
        {
            _sut.Process(packet, (IpPacket)packet.NetworkPacket!, packet.TransportSegment!);
        }

        // Assert
        _sut.GlobalCount.Should().Be(6);
        _sut.CountByConnection[(_ipv4Address1, _referenceIpAddress1, 0, 0)].Should().Be(3);
        _sut.CountByConnection[(_referenceIpAddress2, _ipv6Address1, 0, 0)].Should().Be(3);
        _sut.CountByConnection.Should().Equal(expectedCountByConnection);
        _sut.PerIpResetCount.Should().Equal(expectedPerIpResetCount);
        _sut.CountBySecond.Should().Equal(expectedCountBySecond);
    }

    private CapturedPacket CreateCapturedPacket(
        IPAddress sourceIpAddress,
        IPAddress destinationIpAddress,
        bool tcpResetFlag,
        DateTime time)
    {
        TransportSegment transportSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            tcpFlags: new TcpFlags(rst: tcpResetFlag));
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

        EthernetFrame ethernetFrame = _packetFixtureFactory.CreateEthernetFrameFixture(networkPacket);
        CapturedPacket packet = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: ethernetFrame,
            networkPacket: networkPacket,
            transportSegment: transportSegment,
            capturedDateTime: time);
        return packet;
    }
}