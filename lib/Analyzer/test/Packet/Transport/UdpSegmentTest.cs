// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.UDP;
using Microsoft.PacketCapture.Analyzer.Report;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Transport;

public class UdpSegmentTest
{
    private static readonly byte[] UdpIpPacket =
    [
        0x00, 0x00, 0x5e, 0x00, 0x02, 0x12, 0xb8, 0x85, 0x84, 0xc5, 0x59, 0x56, 0x86, 0xdd,
        0x60, 0x00, 0x00, 0x00, 0x00, 0x29, 0x11, 0x40, 0x2a, 0x01, 0x01, 0x10, 0x00, 0x08,
        0x00, 0x3b, 0x58, 0xab, 0xcb, 0x9f, 0x6b, 0x74, 0x46, 0x21, 0x2a, 0x00, 0x14, 0x50,
        0x40, 0x09, 0x08, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0a, 0xdc, 0xb6,
        0x01, 0xbb, 0x00, 0x29, 0xa7, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Test_UdpSegmentParse()
    {
        // Given
        var ethernetFrame = EthernetFrame.Parse(UdpIpPacket, UdpIpPacket.Length, PacketContentReader);
        var ipPacket = ethernetFrame.NetworkPacket as IpPacket;

        // Then
        Assert.NotNull(ipPacket?.TransportSegment);
        Assert.True(ipPacket.TransportSegment is UdpSegment);

        var udpSegment = (UdpSegment)ipPacket.TransportSegment;

        udpSegment.Should().NotBeNull();
        udpSegment.SourcePort.Should().Be(56502);
        udpSegment.DestinationPort.Should().Be(443);
        udpSegment.Length.Should().Be(41);
        udpSegment.Checksum.Should().Be(0xa7f4);

        udpSegment.Payload.Should().AllSatisfy(b => b.Should().Be(0x00));
    }
}