// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG.Block;

public class EnhancedPacketBlockTest
{
    private static readonly IAnalysisConfiguration Configuration = new DefaultTrafficAnalysisConfiguration(new SessionMetadata());
    private static readonly PacketContentReader PacketContentReader = new(Configuration);

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments()
    {
        // Given
        byte[] hashValue = [97, 98, 99, 100];
        var enhancedPacketBlockOptionBytes = BlockOptionByteConversionUtil.CreateEnhancedPacketBlockOptionBytes(
            comment: "example comment",
            packetFlag: 3,
            dropCount: 10000,
            hashBlockBytes: [1, .. hashValue]);

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);
        var enhancedPacketOption = enhancedPacketBlock.Options;

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(10);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(enhancedPacketBlock.CapturedLength);

        enhancedPacketOption.Should().NotBeNull();
        enhancedPacketOption.Comment.Should().Be("example comment");
        enhancedPacketOption.DropCount.Should().Be(10000);


        enhancedPacketOption.Hash.Should().NotBeNull();
        enhancedPacketOption.Hash.Algorithm.Should().Be(HashAlgorithm.Xor);
        enhancedPacketOption.Hash.Value.Should().BeEquivalentTo(hashValue);
        enhancedPacketOption.Hash.StringValue.Should().Be("abcd");

        enhancedPacketOption.PacketFlag.Should().NotBeNull();
        enhancedPacketOption.PacketFlag.Inbound.Should().BeTrue();
        enhancedPacketOption.PacketFlag.Outbound.Should().BeTrue();
        enhancedPacketOption.PacketFlag.Flag.Should().Be(3);
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_Some_Empty_Options()
    {
        // Given
        var enhancedPacketBlockOptionBytes = BlockOptionByteConversionUtil.CreateEnhancedPacketBlockOptionBytes(
            comment: "",
            packetFlag: 3,
            dropCount: 10000,
            hashBlockBytes: []);


        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);
        var enhancedPacketOption = enhancedPacketBlock.Options;

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(10);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(enhancedPacketBlock.CapturedLength);

        enhancedPacketOption.Should().NotBeNull();
        enhancedPacketOption.Comment.Should().BeNull();
        enhancedPacketOption.DropCount.Should().Be(10000);

        enhancedPacketOption.Hash.Should().BeNull();

        enhancedPacketOption.PacketFlag.Should().NotBeNull();
        enhancedPacketOption.PacketFlag.Inbound.Should().BeTrue();
        enhancedPacketOption.PacketFlag.Outbound.Should().BeTrue();
        enhancedPacketOption.PacketFlag.Flag.Should().Be(3);
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_Empty_Options()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);
        var enhancedPacketOption = enhancedPacketBlock.Options;

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(10);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(enhancedPacketBlock.CapturedLength);

        enhancedPacketOption.Should().BeNull();
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Parse_Too_Few_Bytes_Fails()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream([.. enhancedPacketBlockBytes.Take(5)]);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader));
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Captured_Length_Not_Equal_To_Data_Length_Fails()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [0, 1, 2, 3],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader));
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_Large_Packet_Should_Only_Parse_Headers()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 100,
            originalCapturedLength: 10000,
            data: [.. Enumerable.Range(0, 100).Select(i => (byte)i)],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(100);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(PacketUtils.MaxPacketHeaderSize);
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_Small_Packet_Should_Only_Parse_Headers()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 50,
            originalCapturedLength: 10000,
            data: [.. Enumerable.Range(0, 50).Select(i => (byte)i)],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(50);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(50);
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_Empty_PacketData_Returns_No_Data()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 0,
            originalCapturedLength: 10000,
            data: [],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var enhancedPacketBlock = new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader);

        // Then
        enhancedPacketBlock.Should().NotBeNull();
        enhancedPacketBlock.InterfaceId.Should().Be(123);
        enhancedPacketBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-05 23:18:16.729"));
        enhancedPacketBlock.CapturedLength.Should().Be(0);
        enhancedPacketBlock.OriginalCapturedLength.Should().Be(10000);
        enhancedPacketBlock.Data.Length.Should().Be(0);
        enhancedPacketBlock.Data.Should().BeEquivalentTo(Array.Empty<byte>());
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Valid_Arguments_PacketLength_Longer_Than_PacketData_Fails()
    {
        // Given
        byte[] enhancedPacketBlockOptionBytes = [];

        var enhancedPacketBlockBytes = BlockByteConversionUtil.CreateEnhancedPacketBlockBytes(
            interfaceId: 123,
            timestampHigh: 100,
            timestampLow: 102,
            capturedLength: 10,
            originalCapturedLength: 10000,
            data: [],
            enhancedPacketBlockOptionBytes);

        var memoryStream = new MemoryStream(enhancedPacketBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new EnhancedPacketBlock(binaryReader, enhancedPacketBlockBytes.Length, 1, PacketContentReader));
    }

    [Fact]
    public void Test_EnhancedPacketBlock_Null_Parameters()
    {
        Assert.Throws<ArgumentNullException>(() => new EnhancedPacketBlock(null!, 0, 1, PacketContentReader));
    }
}