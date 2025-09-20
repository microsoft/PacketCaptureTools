// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;

/// <summary>
/// Transmission Control Protocol Segment.
/// </summary>
public class TcpSegment : TransportSegment
{
    private const int DataOffsetWordSize = 4; // 4 bits

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpSegment" /> class.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="nonTruncatedSize">Non-truncated size in bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 16 bytes.</exception>
    public TcpSegment(byte[] packetBytes, int packetStartPosition, long nonTruncatedSize)
    {
        if (packetBytes.Length < 16)
        {
            throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 16 bytes.", nameof(packetBytes));
        }

        NonTruncatedSize = nonTruncatedSize;
        SourcePort = (packetBytes[packetStartPosition + 0] << 8) | packetBytes[packetStartPosition + 1];
        DestinationPort = (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3];
        SequenceNumber = (uint)((packetBytes[packetStartPosition + 4] << 24) | (packetBytes[packetStartPosition + 5] << 16) | (packetBytes[packetStartPosition + 6] << 8) | packetBytes[packetStartPosition + 7]);
        AckNumber = (uint)((packetBytes[packetStartPosition + 8] << 24) | (packetBytes[packetStartPosition + 9] << 16) | (packetBytes[packetStartPosition + 10] << 8) | packetBytes[packetStartPosition + 11]);
        DataOffsetInWords = (uint)(packetBytes[packetStartPosition + 12] >> 4);
        var dataOffsetValue = (int)DataOffsetInWords * DataOffsetWordSize;

        Flags = new TcpFlags(((packetBytes[packetStartPosition + 12] & 0x01) << 8) | packetBytes[packetStartPosition + 13]);
        Window = (packetBytes[packetStartPosition + 14] << 8) | packetBytes[packetStartPosition + 15];
        Payload = packetBytes.Skip(packetStartPosition + dataOffsetValue).ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpSegment" /> class.
    /// </summary>
    /// <param name="sourcePort">The source port.</param>
    /// <param name="destinationPort">The destination port.</param>
    /// <param name="sequenceNumber">The connection sequence number.</param>
    /// <param name="ackNumber">The connection ack number.</param>
    /// <param name="dataOffsetInWords">The header size.</param>
    /// <param name="flags">TCP flag values.</param>
    /// <param name="window">The window size.</param>
    /// <param name="payload">TCP segment payload.</param>
    /// <param name="nonTruncatedSize">Non-truncated size in bytes.</param>
    internal TcpSegment(
        int sourcePort,
        int destinationPort,
        uint sequenceNumber,
        uint ackNumber,
        uint dataOffsetInWords,
        TcpFlags flags,
        int window,
        byte[] payload,
        long nonTruncatedSize)
    {
        NonTruncatedSize = nonTruncatedSize;
        SourcePort = sourcePort;
        DestinationPort = destinationPort;
        SequenceNumber = sequenceNumber;
        AckNumber = ackNumber;
        DataOffsetInWords = dataOffsetInWords;
        Flags = flags ?? throw new ArgumentNullException(nameof(flags));
        Window = window;
        Payload = payload;
    }

    /// <inheritdoc />
    public override TransportSegmentProtocol Protocol => TransportSegmentProtocol.TCP;

    /// <inheritdoc />
    public override byte[] Payload { get; }

    /// <inheritdoc />
    public override int SourcePort { get; }

    /// <inheritdoc />
    public override int DestinationPort { get; }

    /// <summary>
    /// Gets the sequence number.
    /// </summary>
    public uint SequenceNumber { get; }

    /// <summary>
    /// Gets the acknowledgement receipt number.
    /// </summary>
    public uint AckNumber { get; }

    /// <summary>
    /// Gets the size of the TCP header in 32-bit words.
    /// </summary>
    public uint DataOffsetInWords { get; }

    /// <summary>
    /// Gets the flags of 9 1-bit indicators (control bits).
    /// </summary>
    public TcpFlags Flags { get; }

    /// <summary>
    /// Gets the size of the receive window, which specifies the number of window size units.
    /// </summary>
    public int Window { get; }

    /// <summary>
    /// Gets the non-truncated size in bytes.
    /// </summary>
    public long NonTruncatedSize { get; }

    /// <summary>
    /// Gets the size of non-truncated payload in bytes.
    /// </summary>
    public long NonTruncatedPayloadLength => NonTruncatedSize - DataOffset;

    /// <summary>
    /// Gets the size of the TCP header in bytes.
    /// </summary>
    public uint DataOffset => DataOffsetInWords * 4;
}
