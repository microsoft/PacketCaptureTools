// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Base Block Factory.
/// </summary>
/// <param name="configuration">The analysis configuration.</param>
internal class BlockFactory(IAnalysisConfiguration configuration)
{
    private readonly ILogger? _logger = configuration.LoggerFactory?.CreateLogger<BlockFactory>();
    private readonly PacketContentReader _packetContentReader = new(configuration);

    /// <summary>
    /// Read the next block in Binary Reader.
    /// </summary>
    /// <param name="binaryReader">Binary Reader for pcap bytes.</param>
    /// <param name="frameNumber">Frame number in the current packet capture.</param>
    /// <returns>The next base block in Binary reader.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="binaryReader" /> cannot be null.</exception>
    public Block? ReadNextBlock(BinaryReader binaryReader, int frameNumber)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        var blockHeader = new BlockHeaderParser(binaryReader);
        var blockBinaryReader = new BlockBinaryReader(binaryReader, blockHeader.BlockBodyLength);

        Block? block = null;

        switch (blockHeader.BlockType)
        {
            case BlockType.SectionHeader:
                block = new SectionHeaderBlock(blockBinaryReader, blockHeader.BlockBodyLength);
                break;
            case BlockType.InterfaceStatistics:
                block = new InterfaceStatisticsBlock(blockBinaryReader, blockHeader.BlockBodyLength);
                break;
            case BlockType.InterfaceDescription:
                block = new InterfaceDescriptionBlock(blockBinaryReader, blockHeader.BlockBodyLength);
                break;
            case BlockType.EnhancedPacket:
                block = new EnhancedPacketBlock(blockBinaryReader, blockHeader.BlockBodyLength, frameNumber, _packetContentReader);
                break;
            case BlockType.SimplePacket:
                block = new SimplePacketBlock(blockBinaryReader, frameNumber, _packetContentReader);
                break;
            default:
                _logger?.LogWarning("Unable to parse block type: {HeaderBlockType}", blockHeader.BlockType);
                break;
        }

        blockHeader.SetPositionToEndOfBlock(blockBinaryReader.RemainingBlockLength);
        return block;
    }
}
