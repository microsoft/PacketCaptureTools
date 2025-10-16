// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Converter.Packet;

/// <summary>
/// Intermediary data structure for storing Packet specific
/// information.
/// </summary>
public class CapturedPacket
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CapturedPacket" /> class.
    /// </summary>
    /// <param name="payload">A binary sequence representing the whole packet, headers including. Payload is not packet's payload itself.</param>
    /// <param name="originalPacketSize">Original size of the packet.</param>
    /// <param name="timeCaptured">Timestamp of the moment when the packet was captured.</param>
    /// <exception cref="ArgumentException">Throws when <paramref name="payload"/> length is greater than <paramref name="originalPacketSize"/>.</exception>
    public CapturedPacket(byte[] payload, uint originalPacketSize, DateTime timeCaptured)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.Length > originalPacketSize)
        {
            throw new ArgumentException($"'{nameof(payload)}' length ({payload.Length}) cannot be greater than '{nameof(originalPacketSize)}' ({originalPacketSize}).");
        }

        if (originalPacketSize == 0)
        {
            throw new ArgumentException($"'{nameof(originalPacketSize)}' cannot be zero.");
        }

        Payload = payload;
        OriginalPacketSize = originalPacketSize;
        TimeCaptured = timeCaptured;
    }

    /// <summary>
    /// Gets the payload of CapturedPacket.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Gets the size of the captured packet.
    /// </summary>
    public uint OriginalPacketSize { get; }

    /// <summary>
    /// Gets the timestamp of a moment when the packet was captured.
    /// </summary>
    public DateTime TimeCaptured { get; }
}
