// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.PacketCapture.Analyzer.Packet.Record.Tls;

/// <summary>
/// TLS record.
/// </summary>
public class TlsRecord
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TlsRecord" /> class.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    public TlsRecord(byte[] packetBytes, int packetStartPosition)
    {
        int contentTypeValue = packetBytes[packetStartPosition];
        ContentType = EnumExtensions.GetEnumValue<ContentType>(contentTypeValue, $"'{contentTypeValue}' is not a valid TLS content type.");
        Version = (packetBytes[packetStartPosition + 1] << 8) | packetBytes[packetStartPosition + 2];
        Length = (packetBytes[packetStartPosition + 3] << 8) | packetBytes[packetStartPosition + 4];

        if (IsHandshake)
        {
            int messageTypeValue = packetBytes[packetStartPosition + 5];
            MessageType = EnumExtensions.GetEnumValue<MessageType>(messageTypeValue, $"'{messageTypeValue}' is not a valid TLS handshake type.");
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TlsRecord" /> class.
    /// </summary>
    /// <param name="contentType">TLS contenty type.</param>
    /// <param name="version">TLS version.</param>
    /// <param name="length">TLS record length.</param>
    /// <param name="messageType">TLS message type.</param>
    public TlsRecord(ContentType contentType, int version, int length, MessageType messageType)
    {
        ContentType = contentType;
        Version = version;
        Length = length;
        MessageType = messageType;
    }

    /// <summary>
    /// Gets the TLS record content type.
    /// </summary>
    public ContentType ContentType { get; }

    /// <summary>
    /// Gets the TLS record version.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the TLS record length.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets a value indicating whether the TLS record is in a handshake state.
    /// </summary>
    public bool IsHandshake => ContentType == ContentType.Handshake;

    /// <summary>
    /// Gets the TLS record message type.
    /// </summary>
    public MessageType MessageType { get; } = MessageType.Unknown;

    /// <summary>
    /// Try parse a <see cref="TlsRecord" /> from a byte sequence.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="tlsRecord">The parsed TLS record.</param>
    /// <returns>A boolean indicating whether a TLS record was parsed successfully or not.</returns>
    public static bool TryParse(byte[] packetBytes, int packetStartPosition, [NotNullWhen(true)] out TlsRecord? tlsRecord)
    {
        tlsRecord = null;

        try
        {
            tlsRecord = new TlsRecord(packetBytes, packetStartPosition);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Convert a <see cref="TlsRecord" /> to a byte sequence.
    /// </summary>
    /// <returns>A TLS record as a byte sequence.</returns>
    public byte[] ConvertToBytes()
    {
        var resultBytes = new List<byte>();

        var versionLow = (ushort)(Version >> 16);
        var versionHigh = (ushort)(Version & 0xffff);
        var lengthLow = (ushort)(Length >> 16);
        var lengthHigh = (ushort)(Length & 0xffff);

        resultBytes.Add((byte)ContentType);
        resultBytes.Add((byte)versionLow);
        resultBytes.Add((byte)versionHigh);
        resultBytes.Add((byte)lengthLow);
        resultBytes.Add((byte)lengthHigh);
        resultBytes.Add((byte)MessageType);

        return resultBytes.ToArray();
    }
}
