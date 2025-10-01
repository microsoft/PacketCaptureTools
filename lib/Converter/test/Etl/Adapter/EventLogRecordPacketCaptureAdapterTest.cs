// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Etl.Adapter;
using Microsoft.PacketCapture.Converter.Etl.Reader;
using Microsoft.PacketCapture.Converter.Packet;
using Moq;
using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test.Etl.Adapter;

[SupportedOSPlatform("windows")]
public class EventLogRecordPacketCaptureAdapterTest
{
    [Fact]
    public void Constructor_NullAdapters_ArgumentNullException()
    {
        // Arrange
        // Act
        var result = () => _ = new EventLogRecordPacketCaptureAdapter(null!);

        // Assert
        result.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_ValidAdapters_AssignsAdapters()
    {
        // Arrange
        var adapters = new List<ICapturedPacketAdapter<IEventLogRecordWrapper>>
        {
            new PktmonEventAdapter()
        };

        // Act
        var adapter = new EventLogRecordPacketCaptureAdapter(adapters);

        // Assert
        adapter.Adapters.Should().Equal(adapters);
    }

    [Fact]
    public void Convert_NullInput_Null()
    {
        // Arrange
        var pktmonAdapter = new Mock<ICapturedPacketAdapter<IEventLogRecordWrapper>>();

        var adapters = new List<ICapturedPacketAdapter<IEventLogRecordWrapper>>
        {
            pktmonAdapter.Object
        };

        var adapter = new EventLogRecordPacketCaptureAdapter(adapters);

        // Act
        var result = adapter.Convert(null!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Convert_PktmonAdapterReturnsNull_Null()
    {
        // Arrange
        var pktmonAdapter = new Mock<ICapturedPacketAdapter<IEventLogRecordWrapper>>();
        pktmonAdapter.Setup(adptr => adptr.Convert(It.IsAny<IEventLogRecordWrapper>())).Returns((CapturedPacket)null!);

        var adapters = new List<ICapturedPacketAdapter<IEventLogRecordWrapper>>
        {
            pktmonAdapter.Object
        };

        var adapter = new EventLogRecordPacketCaptureAdapter(adapters);
        var record = new Mock<IEventLogRecordWrapper>();

        // Act
        var result = adapter.Convert(record.Object);

        // Assert
        pktmonAdapter.Verify(x => x.Convert(It.IsAny<IEventLogRecordWrapper>()), Times.Once);
        result.Should().BeNull();
    }

    [Fact]
    public void Convert_PktmonAdapterReturnsCapturedPacket_CapturedPacket()
    {
        // Arrange
        var capturedPacket = new CapturedPacket([20, 11, 12], 20, new DateTime(1991, 1, 22));

        var pktmonAdapter = new Mock<ICapturedPacketAdapter<IEventLogRecordWrapper>>();
        pktmonAdapter.Setup(adptr => adptr.Convert(It.IsAny<IEventLogRecordWrapper>())).Returns(capturedPacket);

        var adapters = new List<ICapturedPacketAdapter<IEventLogRecordWrapper>>
        {
            pktmonAdapter.Object
        };

        var adapter = new EventLogRecordPacketCaptureAdapter(adapters);
        var record = new Mock<IEventLogRecordWrapper>();

        // Act
        var result = adapter.Convert(record.Object);

        // Assert
        pktmonAdapter.Verify(x => x.Convert(It.IsAny<IEventLogRecordWrapper>()), Times.Once);
        result.Should().BeEquivalentTo(capturedPacket);
    }
}
