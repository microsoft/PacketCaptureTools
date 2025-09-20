// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG.Block;

public class InterfaceDescriptionBlockTest
{
    [Fact]
    public void Test_InterfaceDescriptionBlock_Valid_Arguments()
    {
        // Given
        var interfaceDescriptionBlockOptionsBytes = BlockOptionByteConversionUtil.CreateInterfaceDescriptionBlockOptionBytes(
            comment: "Example comment",
            name: "example name",
            description: "example description",
            ipv4Address: IPAddress.Parse("127.0.0.1"),
            ipv6Address: IPAddress.Parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            macAddress: PhysicalAddress.Parse("00-00-5E-00-53-AF"),
            euiAddress: new byte[] { 123, 0, 0, 0, 0, 0, 3, 2 },
            speed: 10000L,
            timestampResolution: byte.MaxValue,
            timezone: 10,
            filter: new byte[] { 100, 125 },
            operatingSystem: "Windows 11, 64-bit",
            frameCheckSequence: byte.MinValue,
            timeOffsetSeconds: 100000L);

        var interfaceDescriptionBlockBytes = BlockByteConversionUtil.CreateInterfaceDescriptionBlockBytes(
            linktype: LinkType.Ethernet,
            snapLen: 1000,
            interfaceDescriptionBlockOptionsBytes: interfaceDescriptionBlockOptionsBytes);

        var memoryStream = new MemoryStream(interfaceDescriptionBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When 
        var interfaceDescriptionBlock = new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockBytes.Length);
        var interfaceDescriptionOption = interfaceDescriptionBlock.Options;

        // Then
        interfaceDescriptionBlock.Should().NotBeNull();
        interfaceDescriptionBlock.SnapLength.Should().Be(1000);
        interfaceDescriptionBlock.AssociatedInterfaceId.Should().BeNull();
        interfaceDescriptionBlock.LinkType.Should().Be(LinkType.Ethernet);
        interfaceDescriptionBlock.Type.Should().Be(BlockType.InterfaceDescription);

        interfaceDescriptionOption.Should().NotBeNull();
        interfaceDescriptionOption.Comment.Should().Be("Example comment");
        interfaceDescriptionOption.Name.Should().Be("example name");
        interfaceDescriptionOption.Description.Should().Be("example description");
        interfaceDescriptionOption.IPv4Address.Should().BeEquivalentTo(IPAddress.Parse("127.0.0.1"));
        interfaceDescriptionOption.IPv6Address.Should().BeEquivalentTo(IPAddress.Parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        interfaceDescriptionOption.MacAddress.Should().Be(PhysicalAddress.Parse("00-00-5E-00-53-AF"));
        interfaceDescriptionOption.EuiAddress.Should().BeEquivalentTo(new byte[] { 123, 0, 0, 0, 0, 0, 3, 2 });
        interfaceDescriptionOption.Speed.Should().Be(10000L);
        interfaceDescriptionOption.TimestampResolution.Should().Be(byte.MaxValue);
        interfaceDescriptionOption.TimeZone.Should().Be(10);
        interfaceDescriptionOption.Filter.Should().BeEquivalentTo(new byte[] { 100, 125 });
        interfaceDescriptionOption.OperatingSystem.Should().Be("Windows 11, 64-bit");
        interfaceDescriptionOption.FrameCheckSequence.Should().Be(byte.MinValue);
        interfaceDescriptionOption.TimeOffsetSeconds.Should().Be(100000L);
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Valid_Arguments_Some_Empty_Options()
    {
        // Given
        var interfaceDescriptionBlockOptionsBytes = BlockOptionByteConversionUtil.CreateInterfaceDescriptionBlockOptionBytes(
            comment: "Example comment",
            name: "",
            description: "",
            ipv4Address: IPAddress.None,
            ipv6Address: IPAddress.None,
            macAddress: PhysicalAddress.None,
            euiAddress: new byte[] { 123, 0, 0, 0, 0, 0, 3, 2 },
            speed: 10000L,
            timestampResolution: byte.MaxValue,
            timezone: 10,
            filter: new byte[] { 100, 125 },
            operatingSystem: "",
            frameCheckSequence: byte.MinValue,
            timeOffsetSeconds: 100000L);
        ;

        var interfaceDescriptionBlockBytes = BlockByteConversionUtil.CreateInterfaceDescriptionBlockBytes(
            linktype: LinkType.Ethernet,
            snapLen: 1000,
            interfaceDescriptionBlockOptionsBytes: interfaceDescriptionBlockOptionsBytes);

        var memoryStream = new MemoryStream(interfaceDescriptionBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When 
        var interfaceDescriptionBlock = new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockBytes.Length);
        var interfaceDescriptionOption = interfaceDescriptionBlock.Options;

        // Then
        interfaceDescriptionBlock.Should().NotBeNull();
        interfaceDescriptionBlock.SnapLength.Should().Be(1000);
        interfaceDescriptionBlock.AssociatedInterfaceId.Should().BeNull();
        interfaceDescriptionBlock.LinkType.Should().Be(LinkType.Ethernet);
        interfaceDescriptionBlock.Type.Should().Be(BlockType.InterfaceDescription);

        interfaceDescriptionOption.Should().NotBeNull();
        interfaceDescriptionOption.Comment.Should().Be("Example comment");
        interfaceDescriptionOption.Name.Should().BeNull();
        interfaceDescriptionOption.Description.Should().BeNull();
        interfaceDescriptionOption.IPv4Address.Should().BeNull();
        interfaceDescriptionOption.IPv6Address.Should().BeNull();
        interfaceDescriptionOption.MacAddress.Should().BeNull();
        interfaceDescriptionOption.EuiAddress.Should().BeEquivalentTo(new byte[] { 123, 0, 0, 0, 0, 0, 3, 2 });
        interfaceDescriptionOption.Speed.Should().Be(10000L);
        interfaceDescriptionOption.TimestampResolution.Should().Be(byte.MaxValue);
        interfaceDescriptionOption.TimeZone.Should().Be(10);
        interfaceDescriptionOption.Filter.Should().BeEquivalentTo(new byte[] { 100, 125 });
        interfaceDescriptionOption.OperatingSystem.Should().BeNull();
        interfaceDescriptionOption.FrameCheckSequence.Should().Be(byte.MinValue);
        interfaceDescriptionOption.TimeOffsetSeconds.Should().Be(100000L);
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Valid_Arguments_Empty_Options()
    {
        // Given
        byte[] interfaceDescriptionBlockOptionsBytes = { };

        var interfaceDescriptionBlockBytes = BlockByteConversionUtil.CreateInterfaceDescriptionBlockBytes(
            linktype: LinkType.Ethernet,
            snapLen: 1000,
            interfaceDescriptionBlockOptionsBytes: interfaceDescriptionBlockOptionsBytes);

        var memoryStream = new MemoryStream(interfaceDescriptionBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When 
        var interfaceDescriptionBlock = new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockBytes.Length);
        var interfaceDescriptionOption = interfaceDescriptionBlock.Options;

        // Then
        interfaceDescriptionBlock.Should().NotBeNull();
        interfaceDescriptionBlock.SnapLength.Should().Be(1000);
        interfaceDescriptionBlock.AssociatedInterfaceId.Should().BeNull();
        interfaceDescriptionBlock.LinkType.Should().Be(LinkType.Ethernet);
        interfaceDescriptionBlock.Type.Should().Be(BlockType.InterfaceDescription);

        interfaceDescriptionOption.Should().BeNull();
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Parse_Too_Few_Bytes_Fails()
    {
        // Given
        byte[] interfaceDescriptionBlockOptionsBytes = { };

        var interfaceDescriptionBlockBytes = BlockByteConversionUtil.CreateInterfaceDescriptionBlockBytes(
            linktype: LinkType.Ethernet,
            snapLen: 1000,
            interfaceDescriptionBlockOptionsBytes: interfaceDescriptionBlockOptionsBytes);

        var memoryStream = new MemoryStream(interfaceDescriptionBlockBytes.Take(5).ToArray());
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockBytes.Length));
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Parse_Empty_Stream_Fails()
    {
        // Given
        byte[] interfaceDescriptionBlockBytes = { };

        var memoryStream = new MemoryStream(interfaceDescriptionBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockBytes.Length));
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Parse_Invalid_LinkType()
    {
        // Given
        byte[] linkTypeBytes = { 9, 9 };
        byte[] reservedBits = { 0, 0 };
        byte[] snapLenBytes = { 10, 10 };
        var interfaceDescriptionBlockOptionsBytes = linkTypeBytes.Concat(reservedBits).Concat(snapLenBytes).ToArray();

        var memoryStream = new MemoryStream(interfaceDescriptionBlockOptionsBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<ArgumentException>(() => new InterfaceDescriptionBlock(binaryReader, interfaceDescriptionBlockOptionsBytes.Length));
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Null_Parameters()
    {
        Assert.Throws<ArgumentNullException>(() => new InterfaceDescriptionBlock(null!, 0));
    }
}