// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Packet;
using Moq;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test;

public class CaptureConverterTest
{
    [Fact]
    public void Constructor_NullWriter_ArgumentNullException()
    {
        // Arrange
        Mock<IPacketReader> mockReader = new();

        // Act
        Action sut = () => _ = new CaptureConverter(mockReader.Object, null!);

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NullReader_ArgumentNullException()
    {
        // Arrange
        Mock<IPacketWriter> mockWriter = new();

        // Act
        Action sut = () => _ = new CaptureConverter(null!, mockWriter.Object);

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NoNullInput_DoesNotThrow()
    {
        // Arrange
        Mock<IPacketReader> mockReader = new();
        Mock<IPacketWriter> mockWriter = new();

        // Act
        Action sut = () => _ = new CaptureConverter(mockReader.Object, mockWriter.Object);

        // Assert
        sut.Should().NotThrow();
    }

    [Fact]
    public void Convert_HasNextReturnsFalse_ReadNextAndWritePacketNotCalled()
    {
        // Arrange
        Mock<IPacketReader> mockReader = new();
        mockReader.Setup(reader => reader.HasNext()).Returns(false);

        Mock<IPacketWriter> mockWriter = new();

        CaptureConverter converter = new(mockReader.Object, mockWriter.Object);

        // Act
        converter.Convert();

        // Assert
        mockReader.Verify(reader => reader.ReadNext(), Times.Never());
        mockWriter.Verify(writer => writer.WritePacket(It.IsAny<CapturedPacket>()), Times.Never());
    }

    [Fact]
    public void Convert_HasNextReturnsTrue_ReadNextAndWritePacketCalled()
    {
        // Arrange
        Mock<IPacketReader> mockReader = new();
        mockReader.SetupSequence(reader => reader.HasNext()).Returns(true).Returns(false);
        mockReader.Setup(reader => reader.ReadNext()).Returns(new CapturedPacket([], 10, DateTime.UtcNow));

        Mock<IPacketWriter> mockWriter = new();

        CaptureConverter converter = new(mockReader.Object, mockWriter.Object);

        // Act
        converter.Convert();

        // Assert
        mockReader.Verify(reader => reader.ReadNext(), Times.Once());
        mockWriter.Verify(writer => writer.WritePacket(It.IsAny<CapturedPacket>()), Times.Once());
    }
}
