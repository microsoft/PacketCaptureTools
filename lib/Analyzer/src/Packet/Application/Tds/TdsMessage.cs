// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;

/// <summary>
/// TDS protocol message.
/// </summary>
internal class TdsMessage
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TdsMessage" /> class.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 8 bytes.</exception>
    public TdsMessage(byte[] packetBytes, int packetStartPosition)
    {
        if (packetBytes.Length < 8)
        {
            throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 8 bytes.");
        }

        int messageTypeValue = packetBytes[packetStartPosition];
        Type = EnumExtensions.GetEnumValue<TdsMessageType>(
            lookupValue: messageTypeValue,
            exceptionMessage: $"Invalid value for TDS message type - '{messageTypeValue}'.");
        int statusTypeValue = packetBytes[packetStartPosition + 1];
        Status = EnumExtensions.GetEnumValue<Status>(
            lookupValue: statusTypeValue,
            exceptionMessage: $"Invalid value for TDS status type - '{statusTypeValue}'.");
        Length = (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3];
        Channel = (packetBytes[packetStartPosition + 4] << 8) | packetBytes[packetStartPosition + 5];
        PacketNumber = packetBytes[packetStartPosition + 6];
        Window = packetBytes[packetStartPosition + 7];
        Payload = packetBytes.Skip(packetStartPosition + 8).ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsMessage" /> class.
    /// </summary>
    /// <param name="messageType">The TDS message type.</param>
    /// <param name="status">The TDS status type.</param>
    /// <param name="length">The TDS message length.</param>
    /// <param name="channel">The TDS channel.</param>
    /// <param name="packetNumber">The message packet number.</param>
    /// <param name="window">The message window size.</param>
    /// <param name="payload">The TDS message payload.</param>
    public TdsMessage(
        TdsMessageType messageType,
        Status status,
        int length,
        int channel,
        int packetNumber,
        int window,
        byte[] payload)
    {
        Type = messageType;
        Status = status;
        Length = length;
        Channel = channel;
        PacketNumber = packetNumber;
        Window = window;
        Payload = payload;
    }

    /// <summary>
    /// Gets the TDS message type.
    /// </summary>
    public TdsMessageType Type { get; }

    /// <summary>
    /// Gets the message status.
    /// </summary>
    public Status Status { get; }

    /// <summary>
    /// Gets the message length.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the channel.
    /// </summary>
    public int Channel { get; }

    /// <summary>
    /// Gets the packet number.
    /// </summary>
    public int PacketNumber { get; }

    /// <summary>
    /// Gets the message window.
    /// </summary>
    public int Window { get; }

    /// <summary>
    /// Gets the TDS message payload.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Try parse a TDS protocol message.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="tdsMessage">The parsed TDS message.</param>
    /// <returns>A bool determining wheter a <see cref="TdsMessage" /> was parsed.</returns>
    public static bool TryParse(byte[] packetBytes, int packetStartPosition, [NotNullWhen(true)] out TdsMessage? tdsMessage)
    {
        tdsMessage = null;

        try
        {
            tdsMessage = new TdsMessage(packetBytes, packetStartPosition);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Convert a <see cref="TdsMessage" /> to a byte sequence.
    /// </summary>
    /// <returns>A TDS message as a byte sequence.</returns>
    public byte[] ConvertToBytes()
    {
        var resultBytes = new List<byte>();

        var lengthLow = (ushort)(Length >> 16);
        var lengthHigh = (ushort)(Length & 0xffff);
        var channelLow = (ushort)(Channel >> 16);
        var channelHigh = (ushort)(Channel & 0xffff);

        resultBytes.Add((byte)Type);
        resultBytes.Add((byte)Status);
        resultBytes.Add((byte)lengthLow);
        resultBytes.Add((byte)lengthHigh);
        resultBytes.Add((byte)channelLow);
        resultBytes.Add((byte)channelHigh);
        resultBytes.Add((byte)PacketNumber);
        resultBytes.Add((byte)Window);
        resultBytes.AddRange(Payload);

        return resultBytes.ToArray();
    }
}
