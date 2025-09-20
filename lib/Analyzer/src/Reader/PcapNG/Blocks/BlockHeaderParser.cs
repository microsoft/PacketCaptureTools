// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks
{
    /// <summary>
    /// Base Block from packet capture file.
    /// </summary>
    internal class BlockHeaderParser
    {
        /// <summary>
        /// Minimum total length of bytes for a base block.
        /// </summary>
        public const uint MinimalTotalLength = 12;

        private readonly BinaryReader _binaryReader;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlockHeaderParser" /> class.
        /// </summary>
        /// <param name="binaryReader">Binary Reader for the base block bytes.</param>
        /// <exception cref="ArgumentException">If block type doesn't exist for bytes.</exception>
        /// <exception cref="Exception">If the binary reader does not contain enough bytes for a base block.</exception>
        public BlockHeaderParser(BinaryReader binaryReader)
        {
            _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

            _binaryReader = binaryReader;

            var blockType = binaryReader.ReadUInt32();
            if (!Enum.IsDefined(typeof(BlockType), blockType))
            {
                throw new ArgumentException($"Invalid blockType: {blockType:x}.");
            }

            BlockType = (BlockType)blockType;
            TotalBlockLength = (int)binaryReader.ReadUInt32();

            if (TotalBlockLength < MinimalTotalLength)
            {
                throw new Exception($"Block has insufficient total length of '{TotalBlockLength}', minimum length is '{MinimalTotalLength}'");
            }
        }

        /// <summary>
        /// Gets the block type.
        /// </summary>
        public BlockType BlockType { get; }

        /// <summary>
        /// Gets the total length of the block.
        /// </summary>
        public int TotalBlockLength { get; }

        /// <summary>
        /// Gets the block body length.
        /// </summary>
        public int BlockBodyLength => (int)(TotalBlockLength - MinimalTotalLength);

        /// <summary>
        /// Set the readers stream to the end of the blocks position.
        /// </summary>
        /// <param name="remainderBytes">The number of bytes left in the block.</param>
        public void SetPositionToEndOfBlock(int remainderBytes)
        {
            if (remainderBytes > BlockBodyLength)
            {
                throw new ArgumentOutOfRangeException($"'{nameof(remainderBytes)}' (size '{remainderBytes}') cannot be larger than '{nameof(BlockBodyLength)}', (size '{BlockBodyLength}').");
            }

            _ = _binaryReader.ReadBytes(remainderBytes);

            var remainderLength = TotalBlockLength % PacketUtils.PcapAlignmentBoundary;
            if (remainderLength > 0)
            {
                var paddingLength = PacketUtils.PcapAlignmentBoundary - remainderLength;
                _binaryReader.ReadBytes(paddingLength);
            }

            try
            {
                if (_binaryReader.BaseStream.CanSeek 
                    && _binaryReader.BaseStream.Position == _binaryReader.BaseStream.Length)
                {
                    return;
                }

                var endTotalLength = _binaryReader.ReadUInt32();
                if (TotalBlockLength != endTotalLength)
                {
                    throw new Exception($"Block has different total length fields. Start total length is '{TotalBlockLength}', and end total length is '{endTotalLength}'. This block may be corrupted.");
                }
            } 
            catch (EndOfStreamException)
            {
                // Ignore if we are at the end of the stream.
            }
        }
    }
}
