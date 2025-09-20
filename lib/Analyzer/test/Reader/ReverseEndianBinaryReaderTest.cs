// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader;
using System.IO;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader;

public class ReverseEndianBinaryReaderTest
{
    private readonly MemoryStream _memoryStream;
    private readonly BinaryWriter _writer;

    public ReverseEndianBinaryReaderTest()
    {
        _memoryStream = new MemoryStream();
        _writer = new BinaryWriter(_memoryStream);
    }

    [Theory]
    [InlineData(0x00FF, 0xFF00)]
    public void Test_ReadUInt16_LittleEndianToBigEndian(ushort littleEndianUShort, ushort expectedBigEndianShort)
    {
        // Given
        _writer.Write(littleEndianUShort);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedBigEndianShort, reader.ReadUInt16());
    }

    [Theory]
    [InlineData(0xFF00, 0x00FF)]
    public void Test_ReadUInt16_BigEndianToLittleEndian(ushort bigEndianUShort, ushort expectedLittleEndianShort)
    {
        // Given
        _writer.Write(bigEndianUShort);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedLittleEndianShort, reader.ReadUInt16());
    }

    [Theory]
    [InlineData(0xFF, 0xFF000000)]
    public void Test_ReadUInt32_LittleEndianToBigEndian(uint littleEndianUInt, uint expectedBigEndianUInt)
    {
        // Given
        _writer.Write(littleEndianUInt);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedBigEndianUInt, reader.ReadUInt32());
    }

    [Theory]
    [InlineData(0xFF000000, 0xFF)]
    public void Test_ReadUInt32_BigEndianToLittleEndian(uint bigEndianUInt, uint expectedLittleEndianUInt)
    {
        // Given
        _writer.Write(bigEndianUInt);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedLittleEndianUInt, reader.ReadUInt32());
    }

    [Theory]
    [InlineData(0x0000F642, 0x42F60000)]
    public void Test_ReadInt32_LittleEndianToBigEndian(int littleEndianInt, int expectedBigEndianInt)
    {
        // Given
        _writer.Write(littleEndianInt);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedBigEndianInt, reader.ReadInt32());
    }

    [Theory]
    [InlineData(0x0123456789ABCDEF, 0xEFCDAB8967452301)]
    public void Test_ReadUInt64_BigEndianToLittleEndian(ulong bigEndianLong, ulong expectedLittleEndianLong)
    {
        // Given
        _writer.Write(bigEndianLong);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedLittleEndianLong, reader.ReadUInt64());
    }

    [Theory]
    [InlineData(0xEFCDAB8967452301, 0x0123456789ABCDEF)]
    public void Test_ReadUInt64_LittleEndianToBigEndian(ulong littleEndianLong, ulong expectedBigEndianLong)
    {
        // Given
        _writer.Write(littleEndianLong);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedBigEndianLong, reader.ReadUInt64());
    }

    [Theory]
    [InlineData(0x13A1C5A189374B, 0x4B3789A1C5A11300)]
    public void Test_ReadInt64_BigEndianToLittleEndian(long bigEndianLong, long expectedLittleEndianLong)
    {
        // Given
        _writer.Write(bigEndianLong);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedLittleEndianLong, reader.ReadInt64());
    }

    [Theory]
    [InlineData(0x4B3789A1C5A11300, 0x13A1C5A189374B)]
    public void Test_ReadInt64_LittleEndianToBigEndian(long littleEndianLong, long expectedBigEndianLong)
    {
        // Given
        _writer.Write(littleEndianLong);

        _memoryStream.Position = 0;

        // When
        BinaryReader reader = new ReverseEndianBinaryReader(_memoryStream);

        // Then
        Assert.Equal(expectedBigEndianLong, reader.ReadInt64());
    }
}