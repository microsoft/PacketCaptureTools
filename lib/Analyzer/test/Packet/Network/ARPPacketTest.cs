// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.ARP;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Report;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Network;

public class ArpPacketTest
{
    private static readonly byte[] ArpIpPacket =
    [
        0xe4, 0xb9, 0x7a, 0xf8, 0x5a, 0x51, 0x8c, 0x8c, 0xaa, 0x4e, 0x02, 0x11, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x8c, 0x8c, 0xaa, 0x4e, 0x02, 0x11, 0x0a, 0xa6,
        0xf1, 0x2f, 0xe4, 0xb9, 0x7a, 0xf8, 0x5a, 0x51, 0x0a, 0xa6, 0xf1, 0xa4, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Parse()
    {
        // Given
        var ethernetFrame = EthernetFrame.Parse(ArpIpPacket, ArpIpPacket.Length, PacketContentReader);

        // Then
        Assert.NotNull(ethernetFrame.NetworkPacket);
        Assert.True(ethernetFrame.NetworkPacket is ArpPacket);

        var arpPacket = (ArpPacket)ethernetFrame.NetworkPacket;

        arpPacket.Should().NotBeNull();
        arpPacket.HardwareType.Should().Be(HardwareType.Ethernet);
        arpPacket.EtherType.Should().Be(EtherType.IPv4);
        arpPacket.HardwareAddressLength.Should().Be(6);
        arpPacket.ProtocolAddressLength.Should().Be(4);
        arpPacket.OperationCode.Should().Be(OperationCode.Reply);
        arpPacket.SenderHardwareAddress.ToString().Should().Be("8C8CAA4E0211");
        arpPacket.SenderProtocolAddress.ToString().Should().Be("10.166.241.47");
        arpPacket.TargetHardwareAddress.ToString().Should().Be("E4B97AF85A51");
        arpPacket.TargetProtocolAddress.ToString().Should().Be("10.166.241.164");
        arpPacket.Protocol.Should().Be(NetworkPacketProtocol.ARP);

        ethernetFrame.NetworkPacket.TransportSegment.Should().BeNull();
    }
}