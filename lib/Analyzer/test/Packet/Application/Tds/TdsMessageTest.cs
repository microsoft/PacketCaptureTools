// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;
using System;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Packet.Application.Tds;

public class TdsMessageTest
{
    [Fact]
    public void Constructor_ValidParams_NoException()
    {
        // Arrange
        var tdsMessageBytes = new TdsMessage(
            messageType: TdsMessageType.PreLogin,
            status: Status.EndOfMessage,
            length: 100,
            channel: 100,
            packetNumber: 1,
            window: 100,
            payload: new byte[] { }).ConvertToBytes();

        // Act
        Action action = () => new TdsMessage(tdsMessageBytes, 0);

        // Assert
        action.Should().NotThrow<Exception>();
    }

    [Fact]
    public void Constructor_InvalidParams_ThrowsException()
    {
        // Arrange
        var tdsMessageBytes = new TdsMessage(
            messageType: TdsMessageType.PreLogin,
            status: Status.EndOfMessage,
            length: 100,
            channel: 100,
            packetNumber: 1,
            window: 100,
            payload: new byte[] { }).ConvertToBytes();

        // Act
        Action actionNull = () => new TdsMessage(null!, 0);
        Action actionTooFewBytes = () => new TdsMessage(tdsMessageBytes.Take(7).ToArray(), 0);

        // Assert
        actionNull.Should().Throw<Exception>();
        actionTooFewBytes.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData(TdsMessageType.PreLogin, Status.EndOfMessage)]
    [InlineData(TdsMessageType.Tds7Login, Status.ResetConnectionSkipTransaction)]
    [InlineData(TdsMessageType.SqlBatch, Status.ResetConnection)]
    [InlineData(TdsMessageType.PreTds7Login, Status.Normal)]
    internal void Constructor_ValidParams_Pass(TdsMessageType expectedMessageType, Status expectedStatus)
    {
        // Arrange
        var tdsMessageBytes = new TdsMessage(
            messageType: expectedMessageType,
            status: expectedStatus,
            length: 100,
            channel: 100,
            packetNumber: 1,
            window: 100,
            payload: new byte[] { }).ConvertToBytes();

        // Act
        var message = new TdsMessage(tdsMessageBytes, 0);

        // Assert
        message.Type.Should().Be(expectedMessageType);
        message.Status.Should().Be(expectedStatus);
        message.Length.Should().Be(100);
        message.Channel.Should().Be(100);
        message.PacketNumber.Should().Be(1);
        message.Window.Should().Be(100);
    }
}