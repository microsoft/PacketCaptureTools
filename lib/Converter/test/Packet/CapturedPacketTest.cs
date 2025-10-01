// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Packet;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test.Packet;

public class CapturedPacketTest
{
    [Fact]
    public void Constructor_PayloadLongerThanOriginalSize_ArgumentException()
    {
        // Arrange
        // Act
        Action result = () => _ = new CapturedPacket([22, 23], 1, new DateTime(1970, 1, 1));

        // Assert
        result.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_NullPayload_ArgumentNullException()
    {
        // Arrange
        // Act
        Action result = () => _ = new CapturedPacket(null!, 0, new DateTime(1970, 1, 1));

        // Assert
        result.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_OriginalPayloadSizeZero_ArgumentException()
    {
        // Arrange
        // Act
        Action result = () => _ = new CapturedPacket([], 0, new DateTime(1970, 1, 1));

        // Assert
        result.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_ValidInput_CorrectlyAssigned()
    {   
        // Arrange
        byte[] payload = [11];
        DateTime epochMin = new(1970, 1, 1);
        
        // Act
        CapturedPacket result = new(payload, 1, epochMin);

        // Assert
        result.Payload.Should().BeEquivalentTo(payload);
        result.TimeCaptured.Should().Be(result.TimeCaptured);
        result.OriginalPacketSize.Should().Be(1);
    }
}
