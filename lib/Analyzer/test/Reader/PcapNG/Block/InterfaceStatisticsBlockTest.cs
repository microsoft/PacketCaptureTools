// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG.Block;

public class InterfaceStatisticsBlockTest
{
    [Fact]
    public void Test_InterfaceStatisticsBlock_Parse()
    {
        // Given
        var interfaceStatisticsBlockOptionBytes = BlockOptionByteConversionUtil.CreateInterfaceStatisticsBlockOptionBytes(
            comment: "example comment",
            startTimestampHigh: 9,
            startTimestampLow: 6,
            endimestampHigh: 14,
            endimestampLow: 12,
            interfaceReceived: 100,
            interfaceDrop: 10,
            filterAccept: 100,
            systemDrop: 10,
            deliveredToUser: 100);

        var interfaceStatisticsBlockBytes = BlockByteConversionUtil.CreateInterfaceStatisticsBlockBytes(interfaceId: 10000, timestampHigh: 20, timestampLow: 1, interfaceStatisticsBlockOptionsBytes: interfaceStatisticsBlockOptionBytes);

        var memoryStream = new MemoryStream(interfaceStatisticsBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var interfaceStatisticsBlock = new InterfaceStatisticsBlock(binaryReader, interfaceStatisticsBlockBytes.Length);
        var interfaceStatisticsOption = interfaceStatisticsBlock.Options;

        // Then
        interfaceStatisticsBlock.Should().NotBeNull();
        interfaceStatisticsBlock.InterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-01 23:51:39.345"));
        interfaceStatisticsBlock.AssociatedInterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Type.Should().Be(BlockType.InterfaceStatistics);

        interfaceStatisticsOption.Should().NotBeNull();
        interfaceStatisticsOption.Comment.Should().Be("example comment");
        interfaceStatisticsOption.StartTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00.015"));
        interfaceStatisticsOption.EndTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00.026"));
        interfaceStatisticsOption.InterfaceReceived.Should().Be(100);
        interfaceStatisticsOption.InterfaceDrop.Should().Be(10);
        interfaceStatisticsOption.FilterAccept.Should().Be(100);
        interfaceStatisticsOption.SystemDrop.Should().Be(10);
        interfaceStatisticsOption.DeliveredToUser.Should().Be(100);
    }

    [Fact]
    public void Test_InterfaceStatisticsBlock_Parse_Some_Empty_Options()
    {
        // Given
        var interfaceStatisticsBlockOptionBytes = BlockOptionByteConversionUtil.CreateInterfaceStatisticsBlockOptionBytes(
            comment: "",
            startTimestampHigh: 9,
            startTimestampLow: 6,
            endimestampHigh: 14,
            endimestampLow: 12,
            interfaceReceived: 100,
            interfaceDrop: 0,
            filterAccept: 0,
            systemDrop: 0,
            deliveredToUser: 0);

        var interfaceStatisticsBlockBytes = BlockByteConversionUtil.CreateInterfaceStatisticsBlockBytes(
            interfaceId: 10000,
            timestampHigh: 20,
            timestampLow: 1,
            interfaceStatisticsBlockOptionsBytes: interfaceStatisticsBlockOptionBytes);

        var memoryStream = new MemoryStream(interfaceStatisticsBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var interfaceStatisticsBlock = new InterfaceStatisticsBlock(binaryReader, interfaceStatisticsBlockBytes.Length);
        var interfaceStatisticsOption = interfaceStatisticsBlock.Options;

        // Then
        interfaceStatisticsBlock.Should().NotBeNull();
        interfaceStatisticsBlock.InterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-01 23:51:39.345"));
        interfaceStatisticsBlock.AssociatedInterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Type.Should().Be(BlockType.InterfaceStatistics);

        interfaceStatisticsOption.Should().NotBeNull();
        interfaceStatisticsOption.Comment.Should().BeNull();
        interfaceStatisticsOption.StartTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00.015"));
        interfaceStatisticsOption.EndTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00.026"));
        interfaceStatisticsOption.InterfaceReceived.Should().Be(100);
        interfaceStatisticsOption.InterfaceDrop.Should().Be(0);
        interfaceStatisticsOption.FilterAccept.Should().Be(0);
        interfaceStatisticsOption.SystemDrop.Should().Be(0);
        interfaceStatisticsOption.DeliveredToUser.Should().Be(0);
    }

    [Fact]
    public void Test_InterfaceStatisticsBlock_Parse_Empty_Options()
    {
        // Given
        byte[] interfaceStatisticsBlockOptionBytes = { };

        var interfaceStatisticsBlockBytes = BlockByteConversionUtil.CreateInterfaceStatisticsBlockBytes(
            interfaceId: 10000,
            timestampHigh: 20,
            timestampLow: 1,
            interfaceStatisticsBlockOptionsBytes: interfaceStatisticsBlockOptionBytes);

        var memoryStream = new MemoryStream(interfaceStatisticsBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var interfaceStatisticsBlock = new InterfaceStatisticsBlock(binaryReader, interfaceStatisticsBlockBytes.Length);
        var interfaceStatisticsOption = interfaceStatisticsBlock.Options;

        // Then
        interfaceStatisticsBlock.Should().NotBeNull();
        interfaceStatisticsBlock.InterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Timestamp.Should().Be(DateTime.Parse("1970-01-01 23:51:39.345"));
        interfaceStatisticsBlock.AssociatedInterfaceId.Should().Be(10000);
        interfaceStatisticsBlock.Type.Should().Be(BlockType.InterfaceStatistics);

        interfaceStatisticsOption.Should().BeNull();
    }

    [Fact]
    public void Test_InterfaceStatisticsBlock_Parse_Too_Few_Bytes_Fails()
    {
        // Given
        byte[] interfaceStatisticsBlockOptionBytes = { };

        var interfaceStatisticsBlockBytes = BlockByteConversionUtil.CreateInterfaceStatisticsBlockBytes(
            interfaceId: 10000,
            timestampHigh: 20,
            timestampLow: 1,
            interfaceStatisticsBlockOptionsBytes: interfaceStatisticsBlockOptionBytes);


        var memoryStream = new MemoryStream(interfaceStatisticsBlockBytes.Take(5).ToArray());
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new InterfaceStatisticsBlock(binaryReader, interfaceStatisticsBlockBytes.Length));
    }

    [Fact]
    public void Test_InterfaceStatisticsBlock_Parse_Empty_Stream_Fails()
    {
        // Given
        byte[] interfaceStatisticsBlockBytes = { };

        var memoryStream = new MemoryStream(interfaceStatisticsBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new InterfaceStatisticsBlock(binaryReader, interfaceStatisticsBlockBytes.Length));
    }

    [Fact]
    public void Test_InterfaceStatisticsBlock_Null_Parameters()
    {
        Assert.Throws<ArgumentNullException>(() => new InterfaceStatisticsBlock(null!, 0));
    }
}