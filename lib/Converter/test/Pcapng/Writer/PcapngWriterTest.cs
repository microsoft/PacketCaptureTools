// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Pcapng.Writer;
using Moq;
using System;
using System.IO;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test.Pcapng.Writer;

public class PcapngWriterTest
{
    [Fact]
    public void WritePacket_NullInput_ThrowsException()
    {
        // Arrange
        var pcapngWriterMock = new Mock<PcapngWriter>(new MemoryStream()) { CallBase = true };

        // Act
        Action sut = () => pcapngWriterMock.Object.WritePacket(null!);

        // Assert
        sut.Should().Throw<ArgumentNullException>();
    }
}
