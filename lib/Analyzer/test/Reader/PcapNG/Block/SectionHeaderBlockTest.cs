// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.PcapNG.Block;

public class SectionHeaderBlockTest
{
    [Fact]
    public void Test_SectionHeaderBlock_Valid_Arguments()
    {
        // Given
        var sectionHeaderBlockOptionBytes = BlockOptionByteConversionUtil.CreateSectionHeaderBlockOptionBytes(
            comment: "example comment",
            hardware: "Lenovo x1234 laptop",
            operatingSystem: "Windows 11, 64-bit",
            userApplication: "Pktmon packet capture tool");

        var sectionHeaderBlockBytes = BlockByteConversionUtil.CreateSectionHeaderBlockBytes(
            magicNumber: MagicNumber.Identical,
            majorVersion: 1,
            minorVersion: 1,
            sectionLength: 100,
            sectionHeaderOptionBytes: sectionHeaderBlockOptionBytes);
        var memoryStream = new MemoryStream(sectionHeaderBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var sectionHeaderBlock = new SectionHeaderBlock(binaryReader, sectionHeaderBlockBytes.Length);
        var sectionHeaderOption = sectionHeaderBlock.Options;

        // Then
        sectionHeaderBlock.Should().NotBeNull();
        sectionHeaderBlock.MagicNumber.Should().Be(MagicNumber.Identical);
        sectionHeaderBlock.MajorVersion.Should().Be(1);
        sectionHeaderBlock.MinorVersion.Should().Be(1);
        sectionHeaderBlock.SectionLength.Should().Be(100);

        sectionHeaderOption.Should().NotBeNull();
        sectionHeaderOption.Comment.Should().Be("example comment");
        sectionHeaderOption.Hardware.Should().Be("Lenovo x1234 laptop");
        sectionHeaderOption.OperatingSystem.Should().Be("Windows 11, 64-bit");
        sectionHeaderOption.UserApplication.Should().Be("Pktmon packet capture tool");
    }

    [Fact]
    public void Test_SectionHeaderBlock_Valid_Arguments_Empty_Options()
    {
        // Given
        byte[] sectionHeaderBlockOptionBytes = { };

        var sectionHeaderBlockBytes = BlockByteConversionUtil.CreateSectionHeaderBlockBytes(
            magicNumber: MagicNumber.Identical,
            majorVersion: 1,
            minorVersion: 1,
            sectionLength: 100,
            sectionHeaderOptionBytes: sectionHeaderBlockOptionBytes);
        var memoryStream = new MemoryStream(sectionHeaderBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var sectionHeaderBlock = new SectionHeaderBlock(binaryReader, sectionHeaderBlockBytes.Length);
        var sectionHeaderOption = sectionHeaderBlock.Options;

        // Then
        sectionHeaderBlock.Should().NotBeNull();
        sectionHeaderBlock.MagicNumber.Should().Be(MagicNumber.Identical);
        sectionHeaderBlock.MajorVersion.Should().Be(1);
        sectionHeaderBlock.MinorVersion.Should().Be(1);
        sectionHeaderBlock.SectionLength.Should().Be(100);

        sectionHeaderOption.Should().BeNull();
    }

    [Fact]
    public void Test_SectionHeaderBlock_Valid_Arguments_Some_Empty_Options()
    {
        // Given
        var sectionHeaderBlockOptionBytes = BlockOptionByteConversionUtil.CreateSectionHeaderBlockOptionBytes(
            comment: "",
            hardware: "Lenovo x1234 laptop",
            operatingSystem: "",
            userApplication: "Pktmon packet capture tool");

        var sectionHeaderBlockBytes = BlockByteConversionUtil.CreateSectionHeaderBlockBytes(
            magicNumber: MagicNumber.Identical,
            majorVersion: 1,
            minorVersion: 1,
            sectionLength: 100,
            sectionHeaderOptionBytes: sectionHeaderBlockOptionBytes);
        var memoryStream = new MemoryStream(sectionHeaderBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // When
        var sectionHeaderBlock = new SectionHeaderBlock(binaryReader, sectionHeaderBlockBytes.Length);
        var sectionHeaderOption = sectionHeaderBlock.Options;

        // Then
        sectionHeaderBlock.Should().NotBeNull();
        sectionHeaderBlock.MagicNumber.Should().Be(MagicNumber.Identical);
        sectionHeaderBlock.MajorVersion.Should().Be(1);
        sectionHeaderBlock.MinorVersion.Should().Be(1);
        sectionHeaderBlock.SectionLength.Should().Be(100);

        sectionHeaderOption.Should().NotBeNull();
        sectionHeaderOption.Comment.Should().BeNull();
        sectionHeaderOption.Hardware.Should().Be("Lenovo x1234 laptop");
        sectionHeaderOption.OperatingSystem.Should().BeNull();
        sectionHeaderOption.UserApplication.Should().Be("Pktmon packet capture tool");
    }

    [Fact]
    public void Test_InterfaceDescriptionBlock_Parse_Too_Few_Bytes_Fails()
    {
        // Given
        byte[] sectionHeaderBlockOptionsBytes = { };

        var sectionHeaderBlockBytes = BlockByteConversionUtil.CreateSectionHeaderBlockBytes(
            magicNumber: MagicNumber.Identical,
            majorVersion: 1,
            minorVersion: 1,
            sectionLength: 100,
            sectionHeaderOptionBytes: sectionHeaderBlockOptionsBytes);

        var memoryStream = new MemoryStream(sectionHeaderBlockBytes.Take(5).ToArray());
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new SectionHeaderBlock(binaryReader, sectionHeaderBlockBytes.Length));
    }

    [Fact]
    public void Test_SectionHeaderBlock_Parse_Empty_Stream_Fails()
    {
        // Given
        byte[] sectionHeaderBlockBytes = { };

        var memoryStream = new MemoryStream(sectionHeaderBlockBytes);
        var binaryReader = new BinaryReader(memoryStream);

        // Then
        Assert.Throws<EndOfStreamException>(() => new SectionHeaderBlock(binaryReader, sectionHeaderBlockBytes.Length));
    }

    [Fact]
    public void Test_SectionHeaderBlock_Null_Parameters()
    {
        Assert.Throws<ArgumentNullException>(() => new SectionHeaderBlock(null!, 0));
    }
}