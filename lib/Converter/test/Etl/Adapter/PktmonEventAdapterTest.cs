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
public class PktmonEventAdapterTest
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    private readonly PktmonEventAdapter adapter = new();

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameEvent_ValidCapturedPacket()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            (ushort)160,
            new byte[] { 12, 43, 51 }
        };
        record.Setup(x => x.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(x => x.Id).Returns(160);
        record.Setup(x => x.TimeCreated).Returns(new DateTime(1971, 1, 1));
        record.Setup(x => x.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().NotBeNull();
        packet.OriginalPacketSize.Should().Be(160);
        packet.Payload.Should().BeEquivalentTo([12, 43, 51]);
        packet.TimeCaptured.Should().Be(new DateTime(1971, 1, 1));
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

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameDropEvent_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(170);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidUnsupportedPktmonEvent_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(0);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_PktmonPacketNoDateTime_CapturedPacketWithMinEpochTime()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            (ushort)160,
            new byte[] { 12, 43, 51 }
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(160);
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().NotBeNull();
        packet.OriginalPacketSize.Should().Be(160);
        packet.Payload.Should().BeEquivalentTo([12, 43, 51]);
        packet.TimeCaptured.Should().Be(new DateTime(1970, 1, 1));
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_PktmonEventWithNullGuid_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns((Guid?)null);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_PktmonEventWithNonMatchingGuid_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        record.Setup(rec => rec.ProviderId).Returns(new Guid("1d4f30a9-c8bd-4d73-bb5b-19c90402c5ac"));

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameEventNoPayload_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            (ushort)160
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(160);
        record.Setup(rec => rec.TimeCreated).Returns(new DateTime(1971, 1, 1));
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameEventNoOriginalSize_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            new byte[] { 12, 43, 51 }
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(160);
        record.Setup(rec => rec.TimeCreated).Returns(new DateTime(1971, 1, 1));
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameEventPayloadNotByteArray_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            (ushort)160,
            "This is payload"
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(160);
        record.Setup(rec => rec.TimeCreated).Returns(new DateTime(1971, 1, 1));
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }

    [Fact(Skip = "Platform not supported", SkipUnless = nameof(IsWindows))]
    public void Convert_ValidPktmonPacketFrameEventOriginalSizeNotUShort_Null()
    {
        // Arrange
        var record = new Mock<IEventLogRecordWrapper>();
        var packetParams = new List<object>
        {
            new byte[] { 12, 43, 51 },
            "This is payload"
        };
        record.Setup(rec => rec.ProviderId).Returns(new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"));
        record.Setup(rec => rec.Id).Returns(160);
        record.Setup(rec => rec.TimeCreated).Returns(new DateTime(1971, 1, 1));
        record.Setup(rec => rec.GetPropertyValues(It.IsAny<EventLogPropertySelector>())).Returns(packetParams);

        // Act
        var packet = adapter.Convert(record.Object);

        // Assert
        packet.Should().BeNull();
    }
}
