// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.UDP;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG;
using Microsoft.PacketCapture.Analyzer.Report;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG;

public class PcapNgReaderTest
{
    private static readonly byte[] PcapngBytes = 
        [10, 13, 13, 10, 28, 0, 0, 0, 77, 60, 43, 26, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 28, 0, 0, 0, 1, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0, 255, 255, 0, 0, 9, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 6, 0, 0, 0, 156, 0, 0, 0, 0, 0, 0, 0, 176, 18, 5, 0, 122, 254, 36, 0, 124, 0, 0, 0, 124, 0, 0, 0, 68, 109, 87, 125, 40, 18, 192, 74, 0, 154, 76, 44, 8, 0, 69, 0, 0, 110, 100, 55, 0, 0, 117, 17, 76, 144, 37, 157, 173, 13, 192, 168, 1, 101, 130, 165, 130, 165, 0, 90, 107, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        115, 131, 90, 245, 238, 164, 68, 27, 45, 26, 73, 234, 87, 155, 38, 207, 55, 185, 252, 116, 214, 9, 21, 191, 90, 47, 72, 237, 156, 0, 0, 0, 6, 0, 0, 0, 156, 0, 0, 0, 0, 0, 0, 0, 176, 18, 5, 0, 46, 5, 37, 0, 124, 0, 0, 0, 124, 0, 0, 0, 192, 74, 0, 154, 76, 44, 68, 109, 87, 125, 40, 18, 8, 0, 69, 0, 0, 110, 86, 139, 0, 0, 128, 17, 79, 60, 192, 168, 1, 101, 37, 157, 173, 13, 130, 165, 130, 165, 0, 90, 231, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());

    [Fact]
    public void Test_Valid_PcapNGReader_File_ReadNext_Should_Read_Block_And_Packet()
    {
        Stream stream = new MemoryStream(PcapngBytes);
        using var reader = new PcapNgReader(stream, Configuration);
        reader.HasNext().Should().BeTrue();
        reader.ReadNext().Should().BeAssignableTo<CapturedPacket>();
    }

    [Fact]
    public void Test_Valid_PcapNGReader_File_ReadNext_Should_Read_CapturedPacket()
    {
        Stream stream = new MemoryStream(PcapngBytes);
        using var reader = new PcapNgReader(stream, Configuration);

        reader.HasNext().Should().BeTrue();
        var capturedPacket = reader.ReadNext();

        capturedPacket.Should().NotBeNull();
        capturedPacket.PhysicalFrame.Should().BeAssignableTo<EthernetFrame>();
        capturedPacket.NetworkPacket.Should().BeAssignableTo<IPv4Packet>();
        capturedPacket.TransportSegment.Should().BeAssignableTo<UdpSegment>();
    }

    [Fact]
    public void Test_Valid_PcapNGReader_File_Multiple_ReadNext_Should_Read_CapturedPackets()
    {
        Stream stream = new MemoryStream(PcapngBytes);
        using var reader = new PcapNgReader(stream, Configuration);

        // read first packet
        reader.HasNext().Should().BeTrue();

        var capturedPacket1 = reader.ReadNext();

        capturedPacket1.Should().NotBeNull();
        capturedPacket1.PhysicalFrame.Should().BeAssignableTo<EthernetFrame>();
        capturedPacket1.NetworkPacket.Should().BeAssignableTo<IPv4Packet>();
        capturedPacket1.TransportSegment.Should().NotBeNull();
        capturedPacket1.TransportSegment.Payload.Should().AllSatisfy(b => b.Should().Be(0));

        // read second packet
        reader.HasNext().Should().BeTrue();
        var capturedPacket2 = reader.ReadNext();

        capturedPacket2.Should().NotBeNull();
        capturedPacket2.PhysicalFrame.Should().BeAssignableTo<EthernetFrame>();
        capturedPacket2.NetworkPacket.Should().BeAssignableTo<IPv4Packet>();
        capturedPacket2.TransportSegment.Should().BeAssignableTo<UdpSegment>();
        capturedPacket2.TransportSegment.Payload.Should().AllSatisfy(b => b.Should().Be(0));

        // No other packet packet
        reader.HasNext().Should().BeFalse();
    }

    [Fact]
    public void Test_Valid_PcapNGReader_File_ReadNext_On_Incomplete_File_Should_Fail()
    {
        Stream stream = new MemoryStream([.. PcapngBytes.Take(20)]);
        Action action = () => _ = new PcapNgReader(stream, Configuration);

        action.Should().Throw<EndOfStreamException>();
    }

    [Fact]
    public void Test_Valid_PcapNGReader_Null_Params_Should_Fail()
    {
        Action actionStreamNull = () => _ = new PcapNgReader(stream: null!, Configuration);
        Action actionFilePathNull = () => _ = new PcapNgReader(filePath: null!, Configuration);
        Action actionFilePathEmpty = () => _ = new PcapNgReader(filePath: string.Empty, Configuration);

        actionStreamNull.Should().Throw<ArgumentNullException>();
        actionFilePathNull.Should().Throw<ArgumentException>();
        actionFilePathEmpty.Should().Throw<ArgumentException>();
    }
}