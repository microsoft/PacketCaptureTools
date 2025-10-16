// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Converter.Etl.Reader;
using Microsoft.PacketCapture.Converter.Packet;
using Moq;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Converter.Test.Etl.Reader;

public class EtlPacketReaderTest
{
    private static readonly CapturedPacket packet = new([10, 12, 13], 12, new DateTime(1970, 1, 1));
    
    private readonly Mock<ICapturedPacketAdapter<IEventLogRecordWrapper>> adapter = new();

    [Fact]
    public void Constructor_CorrectInput_CorrectlyAssigned()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        // Act
        Action result = () => _ = new EtlPacketReader(mockEventLogReader.Object, adapter.Object);

        // Assert
        result.Should().NotThrow();
    }

    [Fact]
    public void Constructor_NullReader_ArgumentNullException()
    {
        // Arrange
        // Act
        Action result = () => _ = new EtlPacketReader(null!, adapter.Object);

        // Assert
        result.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NullParser_ArgumentNullException()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        // Act
        Action result = () => _ = new EtlPacketReader(mockEventLogReader.Object, null!);

        // Assert
        result.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void HasNext_NoCachedPacketNextEventPresent_True()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).Returns(packet);

        // Act
        var result = mockedEtlPacketReader.Object.HasNext();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void HasNext_NoCachedCapturedPacketNoNextEvent_False()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).Returns((CapturedPacket)null!);

        // Act
        var result = mockedEtlPacketReader.Object.HasNext();

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void HasNext_NoCachedReaderEndOfStream_FalseFalse()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();
        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns((IEventLogRecordWrapper)null!);

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        // Act
        var endOfStreamCall = mockedEtlPacketReader.Object.HasNext();
        var subsequentCall = mockedEtlPacketReader.Object.HasNext();

        // Assert
        endOfStreamCall.Should().BeFalse();
        subsequentCall.Should().BeFalse();
    }

    [Fact]
    public void HasNext_ValidEventInReaderResultsInCachedCapturedPacket_True()
    {
        // Arrange
        var mockEventLogRecord = new Mock<IEventLogRecordWrapper>();

        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();
        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns(mockEventLogRecord.Object);

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        adapter.Setup(adapter => adapter.Convert(It.IsAny<IEventLogRecordWrapper>())).Returns(packet);

        // Act
        var cacheCapturedPacket = mockedEtlPacketReader.Object.HasNext();
        var cachedCapturedPacketPresent = mockedEtlPacketReader.Object.HasNext();

        // Assert
        cacheCapturedPacket.Should().BeTrue();
        cachedCapturedPacketPresent.Should().BeTrue();
    }

    [Fact]
    public void ReadNext_EndOfStreamTrue_Null()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns((IEventLogRecordWrapper)null!);

        var triggerEndOfStreamState = mockedEtlPacketReader.Object.HasNext();

        // Act
        var result = mockedEtlPacketReader.Object.ReadNext();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ReadNext_CachedEventPresent_ReturnsCachedEvent()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        var mockEventLogRecord = new Mock<IEventLogRecordWrapper>();
        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns(mockEventLogRecord.Object);

        adapter.Setup(adapter => adapter.Convert(It.IsAny<IEventLogRecordWrapper>())).Returns(packet);

        var cacheCapturedPacket = mockedEtlPacketReader.Object.HasNext();

        // Act
        var result = mockedEtlPacketReader.Object.ReadNext();

        // Assert
        result.Should().NotBeNull();
        result.Payload.Should().BeEquivalentTo(packet.Payload);
        result.TimeCaptured.Should().Be(packet.TimeCaptured);
        result.OriginalPacketSize.Should().Be(packet.OriginalPacketSize);
    }

    [Fact]
    public void ReadNext_TriggerEndOfStream_Null()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();
        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns((IEventLogRecordWrapper)null!);

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        // Act
        var result = mockedEtlPacketReader.Object.ReadNext();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ReadNext_EventPresentAndValid_ReturnsEventNoSideEffects()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(reader => reader.ReadNext()).CallBase();

        var mockEventLogRecord = new Mock<IEventLogRecordWrapper>();
        mockEventLogReader.Setup(eventReader => eventReader.ReadEvent()).Returns(mockEventLogRecord.Object);

        adapter.Setup(adapter => adapter.Convert(It.IsAny<IEventLogRecordWrapper>())).Returns(packet);

        // Act
        var result = mockedEtlPacketReader.Object.ReadNext();

        // Assert
        result.Should().NotBeNull();
        result.Payload.Should().BeEquivalentTo(packet.Payload);
        result.TimeCaptured.Should().Be(packet.TimeCaptured);
        result.OriginalPacketSize.Should().Be(packet.OriginalPacketSize);
    }

    [Fact]
    public void ReadNext_EventPresentAndValidAfterMultipleInvalidEvents_SkipsInvalidGracefullyReturnsValidEvent()
    {
        // Arrange
        var mockEventLogReader = new Mock<IEventLogReaderWrapper>();

        var packet = new CapturedPacket([10, 12, 13], 12, new DateTime(1970, 1, 1));

        var mockedEtlPacketReader = new Mock<EtlPacketReader>(mockEventLogReader.Object, adapter.Object);
        mockedEtlPacketReader.Setup(x => x.ReadNext()).CallBase();

        var mockEventLogRecord = new Mock<IEventLogRecordWrapper>();
        mockEventLogReader.Setup(x => x.ReadEvent()).Returns(mockEventLogRecord.Object);

        adapter.SetupSequence(x => x.Convert(It.IsAny<IEventLogRecordWrapper>()))
            .Returns((CapturedPacket)null!)
            .Returns(packet);

        // Act
        var result = mockedEtlPacketReader.Object.ReadNext();

        // Assert
        result.Should().NotBeNull();
        result.Payload.Should().BeEquivalentTo(packet.Payload);
        result.TimeCaptured.Should().Be(packet.TimeCaptured);
        result.OriginalPacketSize.Should().Be(packet.OriginalPacketSize);
    }
}
