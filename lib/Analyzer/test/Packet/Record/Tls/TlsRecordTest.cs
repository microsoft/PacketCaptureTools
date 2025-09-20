// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Record.Tls;

public class TlsRecordTest
{
    [Fact]
    public void Constructor_ValidParams_NoException()
    {
        // Arrange
        var tlsRecordBytes = new TlsRecord(
            contentType: ContentType.Application,
            version: 3,
            length: 120,
            messageType: MessageType.Unknown).ConvertToBytes();

        // Act
        Action action = () => new TlsRecord(tlsRecordBytes, 0);

        // Assert
        action.Should().NotThrow<Exception>();
    }

    [Fact]
    public void Constructor_NullParams_ThrowException()
    {
        // Arrange
        Action action = () => new TlsRecord(null!, 0);

        // Assert
        action.Should().Throw<Exception>();
    }

    [Theory]
    [InlineData(ContentType.Handshake, MessageType.ClientHello)]
    [InlineData(ContentType.Handshake, MessageType.ServerHello)]
    [InlineData(ContentType.ChangeCipherSpec, MessageType.Unknown)]
    [InlineData(ContentType.Alert, MessageType.Unknown)]
    [InlineData(ContentType.Application, MessageType.Unknown)]
    [InlineData(ContentType.Heartbeat, MessageType.Unknown)]
    public void Constructor_ValidParams_Pass(ContentType expectedContentType, MessageType expectedMessageType)
    {
        // Arrange
        var tlsRecordBytes = new TlsRecord(
            contentType: expectedContentType,
            version: 0x0303,
            length: 120,
            messageType: expectedMessageType).ConvertToBytes();

        // Act
        var record = new TlsRecord(tlsRecordBytes, 0);

        // Assert
        record.ContentType.Should().Be(expectedContentType);
        record.Version.Should().Be(3);
        record.Length.Should().Be(120);
        record.MessageType.Should().Be(expectedMessageType);
    }
}