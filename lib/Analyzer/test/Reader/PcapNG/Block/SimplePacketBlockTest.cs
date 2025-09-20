// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG.Block;

public class SimplePacketBlockTest
{
    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 10,
            packetData: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var simplePacketBlock = new SimplePacketBlock(binaryReader, 1, PacketContentReader);

        // Then
        simplePacketBlock.Should().NotBeNull();
        simplePacketBlock.PacketLength.Should().Be(10);
        simplePacketBlock.Data.Should().BeEquivalentTo(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        simplePacketBlock.AssociatedInterfaceId.Should().BeNull();
        simplePacketBlock.Type.Should().Be(BlockType.SimplePacket);
    }

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments_Large_Packet_Should_Only_Parse_Headers()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 100,
            packetData: [.. Enumerable.Range(0, 100).Select(i => (byte)i)]);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var simplePacketBlock = new SimplePacketBlock(binaryReader, 1, PacketContentReader);

        // Then
        simplePacketBlock.Should().NotBeNull();
        simplePacketBlock.PacketLength.Should().Be(100);
        simplePacketBlock.Data.Should().BeEquivalentTo(Enumerable.Range(0, PacketUtils.MaxPacketHeaderSize).Select(i => (byte)i).ToArray());
        simplePacketBlock.Data.Length.Should().Be(PacketUtils.MaxPacketHeaderSize);
        simplePacketBlock.AssociatedInterfaceId.Should().BeNull();
        simplePacketBlock.Type.Should().Be(BlockType.SimplePacket);
    }

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments_Small_Packet_Should_Only_Parse_Headers()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 50,
            packetData: [.. Enumerable.Range(0, 50).Select(i => (byte)i)]);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var simplePacketBlock = new SimplePacketBlock(binaryReader, 1, PacketContentReader);

        // Then
        simplePacketBlock.Should().NotBeNull();
        simplePacketBlock.PacketLength.Should().Be(50);
        simplePacketBlock.Data.Should().BeEquivalentTo(Enumerable.Range(0, 50).Select(i => (byte)i).ToArray());
        simplePacketBlock.Data.Length.Should().Be(50);
        simplePacketBlock.AssociatedInterfaceId.Should().BeNull();
        simplePacketBlock.Type.Should().Be(BlockType.SimplePacket);
    }

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments_0_PacketLength_Returns_No_Data()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 0,
            packetData: [.. Enumerable.Range(0, 100).Select(i => (byte)i)]);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var simplePacketBlock = new SimplePacketBlock(binaryReader, 1, PacketContentReader);

        // Then
        simplePacketBlock.Should().NotBeNull();
        simplePacketBlock.PacketLength.Should().Be(0);
        simplePacketBlock.Data.Should().BeEquivalentTo(Array.Empty<byte>());
        simplePacketBlock.Data.Length.Should().Be(0);
        simplePacketBlock.AssociatedInterfaceId.Should().BeNull();
        simplePacketBlock.Type.Should().Be(BlockType.SimplePacket);
    }

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments_Empty_PacketData_Returns_No_Data()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 0,
            packetData: []);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var simplePacketBlock = new SimplePacketBlock(binaryReader, 1, PacketContentReader);

        // Then
        simplePacketBlock.Should().NotBeNull();
        simplePacketBlock.PacketLength.Should().Be(0);
        simplePacketBlock.Data.Should().BeEquivalentTo(Array.Empty<byte>());
        simplePacketBlock.Data.Length.Should().Be(0);
        simplePacketBlock.AssociatedInterfaceId.Should().BeNull();
        simplePacketBlock.Type.Should().Be(BlockType.SimplePacket);
    }

    [Fact]
    public void Test_SimplePacketBlock_Valid_Arguments_PacketLength_Longer_Than_PacketData_Fails()
    {
        // Given
        var simplePacketBlockBytes = BlockByteConversionUtil.CreateSimplePacketBlockBytes(
            packetLength: 100,
            packetData: []);

        var memoryStream = new MemoryStream(simplePacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new SimplePacketBlock(binaryReader, 1, PacketContentReader));
    }

    [Fact]
    public void Test_SimplePacketBlock_Null_Arguments_Fails()
    {
        Assert.Throws<ArgumentNullException>(() => new SimplePacketBlock(null!, 1, PacketContentReader));
    }
}