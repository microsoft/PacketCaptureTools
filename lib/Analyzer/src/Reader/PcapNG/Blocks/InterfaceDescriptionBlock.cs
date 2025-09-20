// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Interface description .pcapng block.
/// </summary>
internal class InterfaceDescriptionBlock : Block
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InterfaceDescriptionBlock" /> class.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing stream with Interface Description Block bytes.</param>
    /// <param name="blockSizeBytes">The block size in bytes.</param>
    public InterfaceDescriptionBlock(BinaryReader binaryReader, int blockSizeBytes)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        TotalLength = blockSizeBytes;

        var linktype = binaryReader.ReadUInt16();
        if (!Enum.IsDefined(typeof(LinkType), linktype))
        {
            throw new ArgumentException($"Unrecognized link type: {linktype:x}");
        }

        LinkType = (LinkType)linktype;

        _ = binaryReader.ReadUInt16(); // Reserved field.
        SnapLength = binaryReader.ReadInt32();

        if (blockSizeBytes > DefaultSize)
        {
            Options = new InterfaceDescriptionOption(binaryReader, blockSizeBytes - DefaultSize);
        }
    }

    /// <inheritdoc />
    public override int DefaultSize => 8;

    /// <inheritdoc />
    public override BlockType Type => BlockType.InterfaceDescription;

    /// <inheritdoc />
    public override int TotalLength { get; }

    /// <summary>
    /// Gets the link layer type of the interface.
    /// </summary>
    public LinkType LinkType { get; }

    /// <summary>
    /// Gets the maximum number of bytes dumped from each packet.
    /// </summary>
    public int SnapLength { get; }

    /// <summary>
    /// Gets interface description block options.
    /// </summary>
    public InterfaceDescriptionOption? Options { get; }

    /// <inheritdoc />
    public override int? AssociatedInterfaceId => null;
}
