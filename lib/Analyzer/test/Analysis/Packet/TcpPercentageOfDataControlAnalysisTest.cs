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

public class TcpPercentageOfDataControlAnalysisTest
{
    private static readonly DateTime _timeNow = DateTime.Now.TruncateToSeconds();
    private static readonly DateTime _time1 = _timeNow.AddSeconds(5);
    private static readonly DateTime _time2 = _timeNow.AddSeconds(10);

    private static readonly IPAddress _ipv4Address1 = IPAddress.Parse("192.0.1.1");

    private static readonly IPAddress _referenceIpAddress1 = IPAddress.Parse("192.0.0.9");
    private static readonly IPAddress _referenceIpAddress2 = IPAddress.Parse("0:0:0:0:0:0:0:9");

    private static readonly HashSet<IPAddress> _referenceIpAddresses = new HashSet<IPAddress> {
        _referenceIpAddress1,
        _referenceIpAddress2,
    };

    private readonly PacketFixtureFactory _packetFixtureFactory;
    private readonly IPacketFlowDetector _packetFlowDetector;
    private readonly TcpPercentageOfDataControlAnalysis _sut;


    public TcpPercentageOfDataControlAnalysisTest()
    {
        _packetFixtureFactory = new PacketFixtureFactory();
        _packetFlowDetector = new ReferenceIpPacketFlowDetector(_referenceIpAddresses);
        _sut = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);
    }

    [Fact]
    public void Constructor_NullPacketFlowDetectorParameter_ThrowsArgumentNullException()
    {
        // Arrange
        // Act
        Action sut = () => { new TcpPercentageOfDataControlAnalysis(null!); };

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_ValidParameters_ExpectedValues()
    {
        // Arrange
        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>();
        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>();

        // Act
        var sut = new TcpPercentageOfDataControlAnalysis(_packetFlowDetector);

        // Assert
        sut.Should().NotBeNull();
        _sut.TotalTcpBytes.Should().Be(0);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(0);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(0);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(0);
        _sut.PercentageOfTcpControl.Should().Be(0);
        _sut.PercentageOfTcpData.Should().Be(0);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);

    }

    [Fact]
    public void Process_NoPackets_CountersDefaultValues()
    {
        // Arrange
        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>();
        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>();

        // Act
        _sut.Process(null!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(0);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(0);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(0);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(0);
        _sut.PercentageOfTcpControl.Should().Be(0);
        _sut.PercentageOfTcpData.Should().Be(0);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketZeroBytes_AllCountersZero()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 0, 0, _timeNow);

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };
        
        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(0);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(0);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(0);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(0);
        _sut.PercentageOfTcpControl.Should().Be(0);
        _sut.PercentageOfTcpData.Should().Be(0);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyIncomingControlBytesOnly_IncomingAndControlCountersAreTwenty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 20, 0, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 1 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(20);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(20);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(20);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(0);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(1);
        _sut.PercentageOfTcpData.Should().Be(0);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyIncomingDataBytesOnly_IncomingAndDataCountersAreTwenty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 0, 20, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 1 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(20);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(20);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(0);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(20);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0);
        _sut.PercentageOfTcpData.Should().Be(1);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyOutgoingControlBytesOnly_OutgoingAndControlCountersAreTwenty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 0, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 1 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(20);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(20);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(20);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(0);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(1);
        _sut.PercentageOfTcpData.Should().Be(0);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyOutgoingDataBytesOnly_OutgoingAndDataCountersAreTwenty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 0, 20, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 1 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(20);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(20);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(0);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(20);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0);
        _sut.PercentageOfTcpData.Should().Be(1);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyIncomingControlBytesAndDataBytes_ControlAndDataCountersAreTwentyAndPercentsFiftyFifty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 20, 20, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.5 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.5 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(40);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(0);
        _sut.IncomingTcpBytes.Should().Be(40);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(20);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(20);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0.5);
        _sut.PercentageOfTcpData.Should().Be(0.5);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_SinglePacketTwentyOutgoingControlBytesAndDataBytes_ControlAndDataCountersAreTwentyAndPercentsFiftyFifty()
    {
        // Arrange
        CapturedPacket packet = CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 20, _timeNow);

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.5 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.5 }
        };

        // Act
        _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);

        // Assert
        _sut.TotalTcpBytes.Should().Be(40);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(40);
        _sut.IncomingTcpBytes.Should().Be(0);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(20);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(20);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0.5);
        _sut.PercentageOfTcpData.Should().Be(0.5);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_ThreePacketsDifferentControlAndDataBytesSameTime_SixtyPercentControlBytesFourtyPercentDataBytes()
    {
        // Arrange
        var capturedPackets = new List<CapturedPacket>
        {
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 12, _timeNow),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 20, _timeNow),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 20, 8, _timeNow)
        };

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.6 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.4 }
        };

        // Act
        foreach (var packet in capturedPackets)
        {
            _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);
        }

        // Assert
        _sut.TotalTcpBytes.Should().Be(100);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(72);
        _sut.IncomingTcpBytes.Should().Be(28);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(60);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(40);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0.6);
        _sut.PercentageOfTcpData.Should().Be(0.4);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    [Fact]
    public void Process_ThreePacketsDifferentControlAndDataBytesDifferentTimes_SixtyPercentControlBytesFourtyPercentDataBytes()
    {
        // Arrange
        var capturedPackets = new List<CapturedPacket>
        {
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 12, _timeNow),
            CreateCapturedPacket(_referenceIpAddress1, _ipv4Address1, 20, 20, _time1),
            CreateCapturedPacket(_ipv4Address1, _referenceIpAddress1, 20, 8, _time2)
        };

        var expectedControlPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.625 },
            { _time1, 0.5 },
            { _time2, 0.7142857142857143 }
        };

        var expectedDataPerSecondPercent = new Dictionary<DateTime, double>
        {
            { _timeNow, 0.375 },
            { _time1, 0.5 },
            { _time2, 0.2857142857142857}
        };

        // Act
        foreach (var packet in capturedPackets)
        {
            _sut.Process(packet, (IpPacket)packet.NetworkPacket!, (TcpSegment)packet.TransportSegment!);
        }

        // Assert
        _sut.TotalTcpBytes.Should().Be(100);
        _sut.TotalTcpBytes.Should().Be(_sut.IncomingTcpBytes + _sut.OutgoingTcpBytes);
        _sut.OutgoingTcpBytes.Should().Be(72);
        _sut.IncomingTcpBytes.Should().Be(28);
        _sut.TotalTcpControlTrafficBytesPassed.Should().Be(60);
        _sut.TotalTcpDataTrafficBytesPassed.Should().Be(40);
        (_sut.PercentageOfTcpControl + _sut.PercentageOfTcpData).Should().Be(1);
        _sut.PercentageOfTcpControl.Should().Be(0.6);
        _sut.PercentageOfTcpData.Should().Be(0.4);
        _sut.PercentageOfTcpControlPerSecond.Should().Equal(expectedControlPerSecondPercent);
        _sut.PercentageOfTcpDataPerSecond.Should().Equal(expectedDataPerSecondPercent);
    }

    private CapturedPacket CreateCapturedPacket(
        IPAddress sourceIpAddress,
        IPAddress destinationIpAddress,
        uint tcpHeadersize,
        uint tcpPayloadSize,
        DateTime time)
    {
        TransportSegment transportSegment = _packetFixtureFactory.CreateTcpSegmentFixture(
            dataOffset: tcpHeadersize,
            payloadSize: tcpPayloadSize);
        NetworkPacket networkPacket;

        if (sourceIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            networkPacket = _packetFixtureFactory.CreateIPv4PacketFixture(
                transportSegment,
                sourceIpAddress: sourceIpAddress,
                destinationIpAddress: destinationIpAddress);
        }
        else
        {
            throw new Exception("Only IPv4 is supported in this test.");
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