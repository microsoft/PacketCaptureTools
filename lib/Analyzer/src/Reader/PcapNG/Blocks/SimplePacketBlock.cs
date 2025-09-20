// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Simple packet .pcapng file block.
/// </summary>
internal class SimplePacketBlock : Block, IPacketBlock
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SimplePacketBlock" /> class.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing the stream of simple packet block bytes.</param>
    /// <param name="frameNumber">Frame number in the current packet capture.</param>
    /// <param name="packetContentReader">Packet content reader that can read physical frames, network packets and transport segments.</param>
    /// <exception cref="EndOfStreamException">If block contents are less than the simple packet header length.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="binaryReader" /> cannot be null.</exception>
    public SimplePacketBlock(BinaryReader binaryReader, int frameNumber, PacketContentReader packetContentReader)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        int headersLength;
        int remainderLength;
        var payloadLength = 0;
        PacketLength = binaryReader.ReadInt32();

        // only capture the packet headers, not the payload
        if (PacketLength > PacketUtils.MaxPacketHeaderSize)
        {
            headersLength = PacketUtils.MaxPacketHeaderSize;
            payloadLength = PacketLength - headersLength;
            remainderLength = payloadLength % PacketUtils.PcapAlignmentBoundary;
        }
        else
        {
            headersLength = PacketLength;
            remainderLength = PacketLength % PacketUtils.PcapAlignmentBoundary;
        }

        Data = binaryReader.ReadBytes(headersLength);

        // read to the end of captured packet data payload
        _ = binaryReader.ReadBytes(payloadLength);

        if (Data.Length < headersLength)
        {
            throw new EndOfStreamException("Unable to read beyond the end of the stream");
        }

        if (remainderLength > 0)
        {
            var paddingLength = PacketUtils.PcapAlignmentBoundary - remainderLength;
            binaryReader.ReadBytes(paddingLength);
        }

        packetContentReader.TryGetPhysicalFrame(Data, PacketLength, out var physicalFrame);
        CapturedPacket = new CapturedPacket(Data, PacketLength, null, frameNumber, physicalFrame);
    }

    /// <inheritdoc />
    public override int DefaultSize => 4;

    /// <inheritdoc />
    public override BlockType Type => BlockType.SimplePacket;

    /// <inheritdoc />
    public override int TotalLength { get; }

    /// <inheritdoc />
    public override int? AssociatedInterfaceId => null;

    /// <summary>
    /// Gets the length of the packet when it was transmitted on the network.
    /// </summary>
    public int PacketLength { get; }

    /// <summary>
    /// Gets the data coming from the network, including link-layers headers.
    /// </summary>
    public byte[] Data { get; }

    /// <inheritdoc />
    public CapturedPacket CapturedPacket { get; }
}
