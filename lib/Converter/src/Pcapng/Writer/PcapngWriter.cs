// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.IO;
using System.Linq;

namespace Microsoft.PacketCapture.Converter.Pcapng.Writer;

/// <summary>
/// PcapNG file writer.
/// </summary>
public class PcapngWriter : IPacketWriter
{
    /// <summary>
    /// The Section Header Block default size in bytes.
    /// </summary>
    internal const uint SectionHeaderBlockDefaultSize = 16 + MinimalTotalLength;

    /// <summary>
    /// The Interface Description Block default size in bytes.
    /// </summary>
    internal const uint InterfaceDescriptionBlockDefaultSize = 8 + MinimalTotalLength;

    /// <summary>
    /// The Enhanced Packet Block default size in bytes.
    /// </summary>
    internal const uint EnhancedPacketBlockDefaultSize = 20 + MinimalTotalLength;

    private const uint MinimalTotalLength = 12;
    private const int PcapAlignmentBoundary = 4;

    private const uint DefaultInterfaceId = 0;
    private const ushort PcapNgMajorVersion = 1;
    private const ushort PcapNgMinorVersion = 0;
    private const ulong IndefiniteSectionHeaderSize = 0xFFFFFFFFFFFFFFFF;

    private readonly BinaryWriter _binaryWriter;

    /// <summary>
    /// Initializes a new instance of the <see cref="PcapngWriter" /> class.
    /// </summary>
    /// <param name="stream">The stream that the pcapng info will be written to. The stream will be automatically disposed when this writer is disposed.</param>
    public PcapngWriter(Stream stream)
    {
        _ = stream ?? throw new ArgumentNullException(nameof(stream));

        _binaryWriter = new BinaryWriter(stream);

        WriteSectionHeaderBlock();
        WriteInterfaceDescriptionBlock();
    }

    /// <summary>
    /// Writes a <see cref="CapturedPacket"/> to a pcapng file.
    /// </summary>
    /// <param name="packet">An instance of <see cref="CapturedPacket"/>.</param>
    /// <exception cref="ArgumentNullException">Throws if <paramref name="packet"/> is null.</exception>
    public void WritePacket(CapturedPacket packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        WriteEnhancedPacketBlock(packet.Payload, packet.OriginalPacketSize, packet.TimeCaptured);
    }

    /// <summary>
    /// Dispose of the <see cref="PcapngWriter" /> and the underlying <see cref="Stream" />.
    /// </summary>
    public void Dispose()
    {
        _binaryWriter.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Write a new section header block to the pcapng file.
    /// </summary>
    private void WriteSectionHeaderBlock()
    {
        _binaryWriter.Write((uint)BlockType.SectionHeader);
        _binaryWriter.Write(SectionHeaderBlockDefaultSize);

        _binaryWriter.Write((uint)MagicNumber.Identical);
        _binaryWriter.Write(PcapNgMajorVersion);
        _binaryWriter.Write(PcapNgMinorVersion);
        _binaryWriter.Write(IndefiniteSectionHeaderSize);

        _binaryWriter.Write(SectionHeaderBlockDefaultSize);
    }

    /// <summary>
    /// Write interface description block to the pcapng file.
    /// </summary>
    /// <param name="linkType">The network link type.</param>
    /// <param name="snapLen">The maximum number of octets captured in each packet. Default '0' indicates no limit.</param>
    private void WriteInterfaceDescriptionBlock(LinkType linkType = LinkType.Ethernet, uint snapLen = 0)
    {
        _binaryWriter.Write((uint)BlockType.InterfaceDescription);
        _binaryWriter.Write(InterfaceDescriptionBlockDefaultSize);

        _binaryWriter.Write((ushort)linkType);
        _binaryWriter.Write((ushort)0); // reserved field
        _binaryWriter.Write(snapLen);

        _binaryWriter.Write(InterfaceDescriptionBlockDefaultSize);
    }

    /// <summary>
    /// Writes an <see cref="EnhancedPacketBlock" /> to the pcapng file.
    /// </summary>
    /// <param name="payload">The packet payload.</param>
    /// <param name="originalCapturedLength">The original packet length before filtering.</param>
    /// <param name="capturedTime">The time the packet was captured.</param>
    private void WriteEnhancedPacketBlock(byte[] payload, uint originalCapturedLength, DateTime capturedTime)
    {
        _ = payload ?? throw new ArgumentNullException(nameof(payload));

        if (originalCapturedLength < payload.Length)
        {
            throw new ArgumentException($"'{nameof(originalCapturedLength)}' value ({originalCapturedLength}) cannot be less than the '{nameof(payload)}' length ({payload.Length}).");
        }

        if (capturedTime < DateTimeOffset.FromUnixTimeMilliseconds(0))
        {
            throw new ArgumentException($"'{nameof(capturedTime)}' cannot be less than 1970-01-01 00:00:00.");
        }

        var ticks = ((DateTimeOffset)capturedTime).ToUnixTimeMilliseconds() * 1000; // milliseconds
        var timestampHigh = (uint)(ticks >> 32);
        var timestampLow = (uint)(ticks & 0xffffffff);

        var remainderLength = Get32BitPaddingAmount(payload.Length);

        var totalLength = (uint)(EnhancedPacketBlockDefaultSize + payload.Length + remainderLength);

        _binaryWriter.Write((uint)BlockType.EnhancedPacket);
        _binaryWriter.Write(totalLength);
        _binaryWriter.Write(DefaultInterfaceId);
        _binaryWriter.Write(timestampHigh);
        _binaryWriter.Write(timestampLow);
        _binaryWriter.Write(payload.Length);
        _binaryWriter.Write(originalCapturedLength);
        _binaryWriter.Write(payload);

        // pad with 0s to 32-bits (4 bytes)
        foreach (var _ in Enumerable.Range(0, remainderLength))
        {
            _binaryWriter.Write((byte)0);
        }

        _binaryWriter.Write(totalLength);
    }

    /// <summary>
    /// Gets the total number of bytes needed to pad an array to 32-bits (4 bytes).
    /// </summary>
    /// <param name="payloadLength">The length of the packet payload.</param>
    /// <returns>Total number of bytes needed to pad the payload to 32-bits.</returns>
    private static int Get32BitPaddingAmount(int payloadLength)
    {
        return (PcapAlignmentBoundary - (payloadLength % PcapAlignmentBoundary)) % PcapAlignmentBoundary;
    }
}