// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Report;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Transport;

public class TcpSegmentTest
{
    private static readonly byte[] TcpIpPacket = [18, 52, 86, 120, 154, 188, 0, 13, 58, 141, 242, 124, 8, 0, 69, 0, 0, 52, 250, 197, 64, 0, 64, 6, 12, 171, 10, 0, 0, 4, 168, 63, 129, 16, 213, 68, 127, 14, 189, 165, 198, 164, 201, 198, 132, 251, 128, 16, 1, 246, 51, 122, 0, 0, 1, 1, 8, 10, 77, 180, 176, 191, 115, 234, 90, 123];

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Test_TcpSegmentParse()
    {
        // Given
        var ethernetFrame = EthernetFrame.Parse(TcpIpPacket, TcpIpPacket.Length, PacketContentReader);
        var ipv4Packet = ethernetFrame.NetworkPacket as IpPacket;

        // Then
        Assert.NotNull(ipv4Packet?.TransportSegment);
        Assert.True(ipv4Packet.TransportSegment is TcpSegment);

        var tcpSegment = (TcpSegment)ipv4Packet.TransportSegment;
        Assert.True(tcpSegment.Flags.Ack);
        Assert.False(tcpSegment.Flags.Urg);

        Assert.Equal(54596, tcpSegment.SourcePort);
        Assert.Equal(32526, tcpSegment.DestinationPort);
        Assert.Equal(3181758116, tcpSegment.SequenceNumber);
        Assert.Equal(3385230587, tcpSegment.AckNumber);
        Assert.Equal(502, tcpSegment.Window);
        Assert.Equal((uint)8, tcpSegment.DataOffsetInWords);
        Assert.Equal((uint)32, tcpSegment.DataOffset);

        tcpSegment.Payload.Length.Should().Be(0);
    }
}