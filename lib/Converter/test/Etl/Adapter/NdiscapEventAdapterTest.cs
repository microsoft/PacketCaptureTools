// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Etl.Adapter;
using Microsoft.PacketCapture.Converter.Etl.Reader;
using Moq;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test.Etl.Adapter;

[SupportedOSPlatform("windows")]
public class NdiscapEventAdapterTest
{
    private const string ProviderId = "2ed6006e-4729-4609-b423-3ee7bcd678ef";
    private const int EventId = 1001;
    private const uint PacketSize = 3;
    private static readonly byte[] Payload = [1, 2, 3];
    private static readonly DateTime TimeCreated = new(1971, 1, 1);

    private readonly NdiscapEventAdapter adapter = new();

    [Fact]
    public void Convert_ValidNdiscapFragmentEvent_ValidCapturedPacket()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            PacketSize,
            Payload
        };
        record.Setup(x => x.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(x => x.Id).Returns(EventId);
        record.Setup(x => x.TimeCreated).Returns(TimeCreated);
        record.Setup(x => x.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().NotBeNull();
        packet.OriginalPacketSize.Should().Be(PacketSize);
        packet.Payload.Should().BeEquivalentTo(Payload);
        packet.TimeCaptured.Should().Be(TimeCreated);
    }

    [Fact]
    public void Convert_NullEvent_Null()
    {
        // Arrange
        // Act
        var result = adapter.Convert(null!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Convert_ValidUnsupportedNdiscapEvent_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(0);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_NdiscapPacketNoDateTime_CapturedPacketWithMinEpochTime()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            PacketSize,
            Payload
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(EventId);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().NotBeNull();
        packet.OriginalPacketSize.Should().Be(PacketSize);
        packet.Payload.Should().Equal(Payload);
        packet.TimeCaptured.Should().Be(new DateTime(1970, 1, 1));
    }

    [Fact]
    public void Convert_NdiscapEventWithNullGuid_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns((Guid?)null);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_NdiscapEventWithNonMatchingGuid_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns(Guid.NewGuid());

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_NdiscapFragmentEventNoPayload_ReturnsNull()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            PacketSize
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(EventId);
        record.Setup(rec => rec.TimeCreated).Returns(TimeCreated);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_ValidNdiscapPacketNoOriginalSize_ReturnsNull()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            Payload
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(EventId);
        record.Setup(rec => rec.TimeCreated).Returns(TimeCreated);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_ValidNdiscapPacketFrameEventPayloadNotByteArray_ReturnsNull()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            PacketSize,
            "This is the payload"
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(EventId);
        record.Setup(rec => rec.TimeCreated).Returns(TimeCreated);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact]
    public void Convert_ValidNdiscapFragmentEventOriginalSizeNotUint_ReturnsNull()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            Payload,
            "This is payload"
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid(ProviderId));
        record.Setup(rec => rec.Id).Returns(EventId);
        record.Setup(rec => rec.TimeCreated).Returns(TimeCreated);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }
}
