// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Direction;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Packet;

public class PacketCounterAnalysisTest
{
    private static readonly IPAddress _ipv4Address1 = IPAddress.Parse("192.0.1.1");
    private static readonly IPAddress _ipv4Address2 = IPAddress.Parse("192.0.1.2");
    private static readonly IPAddress _ipv4Address3 = IPAddress.Parse("192.0.1.3");
    private static readonly IPAddress _ipv4Address4 = IPAddress.Parse("192.0.1.4");
    private static readonly IPAddress _ipv4Address5 = IPAddress.Parse("192.0.1.5");

    private static readonly IPAddress _ipv6Address1 = IPAddress.Parse("0:0:0:0:0:0:0:1");
    private static readonly IPAddress _ipv6Address2 = IPAddress.Parse("0:0:0:0:0:0:0:2");
    private static readonly IPAddress _ipv6Address3 = IPAddress.Parse("0:0:0:0:0:0:0:3");
    private static readonly IPAddress _ipv6Address4 = IPAddress.Parse("0:0:0:0:0:0:0:4");
    private static readonly IPAddress _ipv6Address5 = IPAddress.Parse("0:0:0:0:0:0:0:5");

    private static readonly IPAddress _referenceIpAddress1 = IPAddress.Parse("192.0.0.9");
    private static readonly IPAddress _referenceIpAddress2 = IPAddress.Parse("0:0:0:0:0:0:0:9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress1,
        _referenceIpAddress2,
    };

    private readonly IPacketFlowDetector _packetFlowDetector;

    private static readonly ISet<int> _tdsPorts = new HashSet<int> { 1433 };

    private readonly PacketFixtureFactory _packetFixtureFactory;

    public PacketCounterAnalysisTest()
    {
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _packetFixtureFactory = new PacketFixtureFactory();
    }

    [Fact]
    public void Constructor_ReferenceIpAddressesParameterNull_ReturnsArgumentNullException()
    {
        // Arrange
        // Act
        Action sut = () => { new PacketCounterAnalysis(null!, _tdsPorts); };

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_TdsPortsParameterNull_ReturnsArgumentNullException()
    {
        // Arrange
        // Act
        Action sut = () => { new PacketCounterAnalysis(_packetFlowDetector, null!); };

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_ValidParameters_ExpectedValues()
    {
        // Arrange
        var expectedCountByPhysicalFrameProtocol = Enum<PhysicalFrameProtocol>.AsDictionary(0);
        var expectedIncomingCountByNetworkPacketProtocol = Enum<NetworkPacketProtocol>.AsDictionary(0);
        var expectedOutgoingCountByNetworkPacketProtocol = Enum<NetworkPacketProtocol>.AsDictionary(0);
        var expectedIncomingCountByTransportSegmentProtocol = Enum<TransportSegmentProtocol>.AsDictionary(0);
        var expectedOutgoingCountByTransportSegmentProtocol = Enum<TransportSegmentProtocol>.AsDictionary(0);
        var expectedCountByTime = new Dictionary<DateTime, int>();
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>();

        // Act
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Assert
        sut.GlobalPacketCount.Should().Be(0);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol.Should().BeEquivalentTo(expectedCountByPhysicalFrameProtocol);
        sut.IncomingCountByNetworkPacketProtocol.Should().BeEquivalentTo(expectedIncomingCountByNetworkPacketProtocol);
        sut.OutgoingCountByNetworkPacketProtocol.Should().BeEquivalentTo(expectedOutgoingCountByNetworkPacketProtocol);
        sut.IncomingCountByTransportSegmentProtocol.Should().BeEquivalentTo(expectedIncomingCountByTransportSegmentProtocol);
        sut.OutgoingCountByTransportSegmentProtocol.Should().BeEquivalentTo(expectedOutgoingCountByTransportSegmentProtocol);
        sut.CountByTime.Should().BeEquivalentTo(expectedCountByTime);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_NoPackets_AllCountersEqualZero()
    {
        // Arrange
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(null!);

        // Assert
        sut.GlobalPacketCount.Should().Be(0);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEmpty();
        sut.PerIpPacketCounters.Should().BeEmpty();
    }

    [Fact]
    public void Process_OneIncomingIpv4Packet_IncomingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(1);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneOutgoingIpv4Packet_OutgoingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(), 
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneIncomingIpv6Packet_IncomingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv6Address1, _referenceIpAddress2);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv6Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(1);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneOutgoingIpv6Packet_OutgoingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress2, _ipv6Address1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv6Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneIncomingTdsPacket_IncomingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 0, _tdsPorts.First());
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(1);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(1);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneOutgoingTdsPacket_OutgoingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, _tdsPorts.First());
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(1);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneIpv4PacketWithBothAddressesAsReferenceIps_OutgoingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _referenceIpAddress1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _referenceIpAddress1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneArpPacket_IncomingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateArpCapturedPacket(_ipv4Address1, _referenceIpAddress1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 0
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(1);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_OneArpPacket_OutgoingCountersEqualOne()
    {
        // Arrange
        CapturedPacket packet = CreateArpCapturedPacket(_referenceIpAddress1, _ipv4Address1);
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 0
                }
            },
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                1
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        sut.Process(packet);

        // Assert
        sut.GlobalPacketCount.Should().Be(1);
        sut.IncomingTdsPacketCount.Should().Be(0);
        sut.OutgoingTdsPacketCount.Should().Be(0);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(1);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(0);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(0);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(1);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(0);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    [Fact]
    public void Process_TwentyIncomingAndOutgoingIpTdsAndArpPackets_GlobalPacketCounterEqualToPerIpPacketCounter()
    {
        // Arrange
        int sumOfPacketsFromAllIps = 0;
        var capturedPackets = new List<CapturedPacket> {
            // Ipv4 source, Ipv4 destination, outgoing
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address2, _tdsPorts.First(), 0),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address3, _tdsPorts.First(), 0),
            // Ipv4 source, Ipv6 destination, incoming
            CreateCapturedPacket(_ipv4Address3, _referenceIpAddress2),
            CreateCapturedPacket(_ipv4Address4, _referenceIpAddress2, 0, _tdsPorts.First()),
            CreateCapturedPacket(_ipv4Address5, _referenceIpAddress2, 0, _tdsPorts.First()),
            // Ipv6 source, Ipv4 destination, incoming
            CreateCapturedPacket(_ipv6Address1, _referenceIpAddress1),
            CreateCapturedPacket(_ipv6Address1, _referenceIpAddress1, 0, _tdsPorts.First()),
            CreateCapturedPacket(_ipv6Address2, _referenceIpAddress1, 0, _tdsPorts.First()),
            // Ipv6 source, Ipv6 destination, outgoing
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address2),
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address3),
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address4, _tdsPorts.First(), 0),
            CreateCapturedPacket(_referenceIpAddress2, _ipv6Address5, _tdsPorts.First(), 0),
            // ARP Packets
            CreateArpCapturedPacket(_referenceIpAddress1, _ipv4Address1),
            CreateArpCapturedPacket(_referenceIpAddress1, _ipv4Address2),
            CreateArpCapturedPacket(_referenceIpAddress1, _ipv4Address3),
            CreateArpCapturedPacket(_referenceIpAddress1, _ipv4Address4),
            CreateArpCapturedPacket(_ipv6Address1, _referenceIpAddress2),
        };
        var expectedPerIpPacketCounters = new Dictionary<IPAddress, PerIpCounterMetrics>
        {
            {
                _ipv4Address1, 
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 4,
                    TdsPacketCount = 0,
                    TcpPacketCount = 3
                } 
            },
            {
                _ipv4Address2,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 2,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
            {
                _ipv4Address3,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 3,
                    TdsPacketCount = 1,
                    TcpPacketCount = 2
                }
            },
            {
                _ipv4Address4,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 2,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
            {
                _ipv4Address5,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
            {
                _ipv6Address1,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 3,
                    TdsPacketCount = 1,
                    TcpPacketCount = 2
                }
            },
            {
                _ipv6Address2,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 2,
                    TdsPacketCount = 1,
                    TcpPacketCount = 2
                }
            },
            {
                _ipv6Address3,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 0,
                    TcpPacketCount = 1
                }
            },
            {
                _ipv6Address4,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            },
            {
                _ipv6Address5,
                new PerIpCounterMetrics
                {
                    TotalPacketCount = 1,
                    TdsPacketCount = 1,
                    TcpPacketCount = 1
                }
            }
        };
        var expectedDateTimeCounter = new Dictionary<DateTime, int>
        {
            {
                DateTime.UtcNow.TruncateToSeconds(),
                20
            },
        };
        var sut = new PacketCounterAnalysis(_packetFlowDetector, _tdsPorts);

        // Act
        foreach (var capturedPacket in capturedPackets)
        {
            sut.Process(capturedPacket);
        }

        // Assert
        sumOfPacketsFromAllIps = sut.PerIpPacketCounters.Sum(ip => ip.Value.TotalPacketCount);
        sut.GlobalPacketCount.Should().Be(capturedPackets.Count);
        sut.GlobalPacketCount.Should().Be(sumOfPacketsFromAllIps);
        sut.IncomingTdsPacketCount.Should().Be(4);
        sut.OutgoingTdsPacketCount.Should().Be(4);
        sut.CountByPhysicalFrameProtocol[PhysicalFrameProtocol.ETH2].Should().Be(capturedPackets.Count);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(3);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv4].Should().Be(5);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(3);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.IPv6].Should().Be(4);
        sut.IncomingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(1);
        sut.OutgoingCountByNetworkPacketProtocol[NetworkPacketProtocol.ARP].Should().Be(4);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(6);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.TCP].Should().Be(9);
        sut.IncomingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.OutgoingCountByTransportSegmentProtocol[TransportSegmentProtocol.UDP].Should().Be(0);
        sut.CountByTime.Should().BeEquivalentTo(expectedDateTimeCounter);
        sut.PerIpPacketCounters.Should().BeEquivalentTo(expectedPerIpPacketCounters);
    }

    private CapturedPacket CreateCapturedPacket(
      IPAddress sourceIpAddress,
      IPAddress destinationIpAddress,
      int sourcePort = 0,
      int destinationPort = 0)
    {
        TransportSegment transportSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            sourcePort: sourcePort,
            destinationPort: destinationPort);
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
            throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(sourceIpAddress));
        }

        EthernetFrame ethernetFrame = _packetFixtureFactory.CreateEthernetFrameFixture(networkPacket);
        CapturedPacket packet = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: ethernetFrame,
            networkPacket: networkPacket,
            transportSegment: transportSegment,
            capturedDateTime: DateTime.UtcNow);
        return packet;
    }

    private CapturedPacket CreateArpCapturedPacket(
        IPAddress sourceIpAddress,
        IPAddress destinationIpAddress)
    {
        TransportSegment? transportSegment = null;
        NetworkPacket networkPacket = _packetFixtureFactory.CreateArpPacketFixture(
                senderProtocolAddress: sourceIpAddress,
                targetProtocolAddress: destinationIpAddress);

        EthernetFrame ethernetFrame = _packetFixtureFactory.CreateEthernetFrameFixture(
            networkPacket,
            EtherType.ARP);

        CapturedPacket packet = _packetFixtureFactory.CreateCapturedPacketFixture(
            physicalFrame: ethernetFrame,
            networkPacket: networkPacket,
            transportSegment: transportSegment,
            capturedDateTime: DateTime.UtcNow);
        return packet;
    }
}