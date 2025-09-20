// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Enhanced packet block.
/// </summary>
internal class EnhancedPacketBlock : Block, IPacketBlock
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EnhancedPacketBlock" /> class.
    /// An Enhanced Packet Block is the standard container for storing the packets coming from the network.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing the stream of Enhanced packet block bytes.</param>
    /// <param name="blockSizeBytes">The block size in bytes.</param>
    /// <param name="frameNumber">Frame number in the current packet capture.</param>
    /// <param name="packetContentReader">Packet content reader that can read physical frames, network packets and transport segments.</param>
    /// <exception cref="EndOfStreamException">If block contents are less than the Enhanced packet header length.</exception>
    public EnhancedPacketBlock(BinaryReader binaryReader, int blockSizeBytes, int frameNumber, PacketContentReader packetContentReader)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        int headersLength;
        int remainderLength;
        var payloadLength = 0;

        TotalLength = blockSizeBytes;
        InterfaceId = binaryReader.ReadInt32();

        TimestampHigh = binaryReader.ReadUInt32();
        TimestampLow = binaryReader.ReadUInt32();
        var milliseconds = (((long)TimestampHigh << 32) + TimestampLow) / 1000;

        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds).UtcDateTime;

        CapturedLength = binaryReader.ReadInt32();
        OriginalCapturedLength = binaryReader.ReadInt32();

        // only capture the packet headers, not the payload
        if ((int)CapturedLength > PacketUtils.MaxPacketHeaderSize)
        {
            headersLength = PacketUtils.MaxPacketHeaderSize;
            payloadLength = (int)CapturedLength - headersLength;
            remainderLength = payloadLength % PacketUtils.PcapAlignmentBoundary;
        }
        else
        {
            headersLength = (int)CapturedLength;
            remainderLength = (int)CapturedLength % PacketUtils.PcapAlignmentBoundary;
        }

        Data = binaryReader.ReadBytes(headersLength);

        // read to the end of captured packet data payload
        _ = binaryReader.ReadBytes(payloadLength);
        blockSizeBytes -= headersLength + remainderLength + payloadLength;

        if (Data.Length < headersLength)
        {
            throw new EndOfStreamException("Unable to read beyond the end of the stream");
        }

        if (remainderLength > 0)
        {
            var paddingLength = PacketUtils.PcapAlignmentBoundary - remainderLength;
            binaryReader.ReadBytes(paddingLength);
        }

        if (blockSizeBytes > DefaultSize)
        {
            Options = new EnhancedPacketOption(binaryReader, blockSizeBytes - DefaultSize);
        }

        packetContentReader.TryGetPhysicalFrame(Data, OriginalCapturedLength.Value, out var physicalFrame);
        CapturedPacket = new CapturedPacket(Data, OriginalCapturedLength.Value, Timestamp, frameNumber, physicalFrame);
    }

    /// <inheritdoc />
    public override int DefaultSize => 28;

    /// <inheritdoc />
    public override BlockType Type => BlockType.EnhancedPacket;

    /// <inheritdoc />
    public override int TotalLength { get; }

    /// <inheritdoc />
    public override int? AssociatedInterfaceId => InterfaceId;

    /// <summary>
    /// Gets an unsigned value that specifies the interface on which this packet was received or transmitted.
    /// </summary>
    public int InterfaceId { get; }

    /// <summary>
    /// Gets a timestamp from when the packet was captured on the original device.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Gets a timestamp from when the packet was captured on the original device.
    /// </summary>
    public uint TimestampHigh { get; }

    /// <summary>
    /// Gets a timestamp from when the packet was captured on the original device.
    /// </summary>
    public uint TimestampLow { get; }

    /// <summary>
    /// Gets an unsigned value that indicates the number of octets captured from the packet after device filtering.
    /// </summary>
    public int? CapturedLength { get; }

    /// <summary>
    /// Gets an unsigned value that indicates the number of octets originally that made up the packet before filtering.
    /// </summary>
    public int? OriginalCapturedLength { get; }

    /// <summary>
    /// Gets the data coming from the network, including link-layer headers.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the enhanced packet block options.
    /// </summary>
    public EnhancedPacketOption? Options { get; }

    /// <inheritdoc />
    public CapturedPacket CapturedPacket { get; }
}
