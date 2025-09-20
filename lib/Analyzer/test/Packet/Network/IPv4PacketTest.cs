// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Report;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Network;

public class IPv4PacketTest
{
    private static readonly byte[] TcpIpPacket = [0, 13, 58, 141, 242, 124, 18, 52, 86, 120, 154, 188, 8, 0, 69, 0, 0, 52, 15, 49, 64, 0, 128, 6, 184, 63, 168, 63, 129, 16, 10, 0, 0, 4, 127, 14, 213, 72, 27, 73, 97, 210, 196, 26, 98, 248, 128, 16, 32, 19, 93, 231, 0, 0, 1, 1, 8, 10, 115, 234, 90, 131, 77, 180, 176, 199];

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Parse()
    {
        // Given
        var ethernetFrame = EthernetFrame.Parse(TcpIpPacket, TcpIpPacket.Length, PacketContentReader);

        // Then
        Assert.NotNull(ethernetFrame.NetworkPacket);
        Assert.True(ethernetFrame.NetworkPacket is IpPacket);

        var ipv4Packet = (IPv4Packet)ethernetFrame.NetworkPacket;

        Assert.True(ipv4Packet.IpProtocol is IpProtocol.TCP);
        Assert.Equal("10.0.0.4", ipv4Packet.DestinationAddress.ToString());
        Assert.Equal(4, ipv4Packet.Version);
        Assert.Equal(5, ipv4Packet.HeaderLengthInWords);
        Assert.Equal(DscpValue.DF, ipv4Packet.DscpValue);
        Assert.Equal(IPv4Flag.DF, ipv4Packet.Flags);
        Assert.Equal(3889, ipv4Packet.Identification);
        Assert.Equal(128, ipv4Packet.TimeToLive);
        Assert.Equal(52, ipv4Packet.TotalLength);

        ethernetFrame.NetworkPacket.TransportSegment!.Payload.Length.Should().Be(0);
    }
}