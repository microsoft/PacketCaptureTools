// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Section Header pcapng block.
/// </summary>
internal sealed class SectionHeaderBlock : Block
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SectionHeaderBlock" /> class.
    /// The Section Header Block is mandatory. It identifies the beginning of a section of the capture dump file. The Section Header Block
    /// does not contain data but it rather identifies a list of blocks (interfaces, packets) that are logically correlated.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing stream with Section Header Block bytes.</param>
    /// <param name="blockSizeBytes">The block size in bytes.</param>
    public SectionHeaderBlock(BinaryReader binaryReader, int blockSizeBytes)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        TotalLength = blockSizeBytes;
        var tempMagicNumber = binaryReader.ReadUInt32();

        if (!Enum.IsDefined(typeof(MagicNumber), tempMagicNumber))
        {
            throw new ArgumentException($"Unrecognized PcapNG magic number: {tempMagicNumber:x}");
        }

        MagicNumber = (MagicNumber)tempMagicNumber;

        MajorVersion = binaryReader.ReadUInt16();
        MinorVersion = binaryReader.ReadUInt16();
        SectionLength = binaryReader.ReadInt64();

        blockSizeBytes -= DefaultSize;

        if (blockSizeBytes > DefaultSize)
        {
            Options = new SectionHeaderOption(binaryReader, blockSizeBytes - DefaultSize);
        }
    }

    /// <inheritdoc />
    public override int DefaultSize => 16;

    /// <inheritdoc />
    public override BlockType Type => BlockType.SectionHeader;

    /// <inheritdoc />
    public override int TotalLength { get; }

    /// <summary>
    /// Gets the magic number that can be used to distinguish sections that have been saved on little-endian machines
    /// from the ones saved on big-endian machines.
    /// </summary>
    public MagicNumber MagicNumber { get; }

    /// <summary>
    /// Gets the string representation of the magic number for this section.
    /// </summary>
    public string MagicNumberString => ((uint)MagicNumber).ToString("x");

    /// <summary>
    /// Gets the number of the current major version of the pcapng format.
    /// </summary>
    public ushort MajorVersion { get; }

    /// <summary>
    /// Gets the number of the current minor version of the pcapng format.
    /// </summary>
    public ushort MinorVersion { get; }

    /// <summary>
    /// Gets a signed value specifying the length in octets of the following section, excluding the Section Header Block itself.
    /// </summary>
    public long SectionLength { get; }

    /// <summary>
    /// Gets Section Header options fields.
    /// </summary>
    public SectionHeaderOption? Options { get; }

    /// <summary>
    /// Gets a value indicating whether the computer and stream endianness are different (See comment MagicNumber)
    /// Examples:   System endianness -> LitleEndian, Stream Endiannes BigEndian -> IsDifferentEndian -> true
    /// System endianness -> LitleEndian, Stream Endiannes LitleEndian -> IsDifferentEndian -> false.
    /// </summary>
    public bool IsDifferentEndian => MagicNumber == MagicNumber.Swapped;

    /// <inheritdoc />
    public override int? AssociatedInterfaceId => null;
}
