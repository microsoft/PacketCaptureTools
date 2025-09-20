// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Interface Statistics pcap block.
/// </summary>
internal class InterfaceStatisticsBlock : Block
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InterfaceStatisticsBlock" /> class.
    /// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing stream with Interface Statistics Block bytes.</param>
    /// <param name="blockSizeBytes">The block size in bytes.</param>
    public InterfaceStatisticsBlock(BinaryReader binaryReader, int blockSizeBytes)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        TotalLength = blockSizeBytes;

        InterfaceId = binaryReader.ReadInt32();

        var unixCapturedTimeHigh = binaryReader.ReadUInt32();
        var unixCapturedTimeLow = binaryReader.ReadUInt32();
        var milliseconds = (((long)unixCapturedTimeHigh << 32) + unixCapturedTimeLow) / 1000;

        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds).UtcDateTime;

        if (blockSizeBytes > DefaultSize)
        {
            Options = new InterfaceStatisticsOption(binaryReader, blockSizeBytes - DefaultSize);
        }
    }

    /// <inheritdoc />
    public override int DefaultSize => 12;

    /// <inheritdoc />
    public override BlockType Type => BlockType.InterfaceStatistics;

    /// <inheritdoc />
    public override int TotalLength { get; }

    /// <summary>
    /// Gets an unsigned value that specifies the interface on which this packet was received or transmitted.
    /// </summary>
    public int InterfaceId { get; }

    /// <summary>
    /// Gets information about relations between packet and interface on which it was captured.
    /// </summary>
    public override int? AssociatedInterfaceId => InterfaceId;

    /// <summary>
    /// Gets a single 64-bit unsigned integer that represents the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Gets Interface Statistics options fields.
    /// </summary>
    public InterfaceStatisticsOption? Options { get; }
}
