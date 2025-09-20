// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG;

/// <summary>
/// A packet reader for .pcapng packet capture files.
/// </summary>
internal class PcapNgReader : IReader
{
    private readonly BlockFactory _blockFactory;
    private readonly BinaryReader _binaryReader;
    private readonly Queue<CapturedPacket> _cachedPackets;
    private bool _isReaderAtEndOfStream;
    private int _frameNumber = 1;

    /// <summary>
    /// Initializes a new instance of the <see cref="PcapNgReader" /> class.
    /// </summary>
    /// <param name="filePath">The .pcapng packet capture file path.</param>
    /// <param name="configuration">The analysis configuration.</param>
    public PcapNgReader(string filePath, IAnalysisConfiguration configuration)
        : this(new FileStream(filePath ?? throw new ArgumentNullException(nameof(filePath)), FileMode.Open, FileAccess.Read, FileShare.Read), configuration)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PcapNgReader" /> class.
    /// </summary>
    /// <param name="stream">A stream containing the .pcapng file bytes.</param>
    /// <param name="configuration">The analysis configuration.</param>
    public PcapNgReader(Stream stream, IAnalysisConfiguration configuration)
    {
        _ = stream ?? throw new ArgumentNullException(nameof(stream));

        _blockFactory = new BlockFactory(configuration);
        _cachedPackets = new Queue<CapturedPacket>();
        _binaryReader = GetBinaryReader(stream);
    }

    /// <inheritdoc />
    public CapturedPacket? ReadNext()
    {
        if (_cachedPackets.Any())
        {
            return _cachedPackets.Dequeue();
        }

        if (_isReaderAtEndOfStream)
        {
            return null;
        }

        try
        {
            while (true)
            {
                var block = _blockFactory.ReadNextBlock(_binaryReader, _frameNumber);

                if (block is IPacketBlock packetBlock)
                {
                    _frameNumber++;
                    return packetBlock.CapturedPacket;
                }
            }
        }
        catch (EndOfStreamException)
        {
            _isReaderAtEndOfStream = true;
        }

        return null;
    }

    /// <inheritdoc />
    public bool HasNext()
    {
        if (_cachedPackets.Any())
        {
            return true;
        }

        if (_isReaderAtEndOfStream)
        {
            return false;
        }

        var packetCheck = ReadNext();
        if (packetCheck is not null)
        {
            _cachedPackets.Enqueue(packetCheck);
            return true;
        }

        return false;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _binaryReader.Dispose();
        _cachedPackets.Clear();
    }

    /// <summary>
    /// Get a binary reader that is either using a reversed endianness or not, depending on the packet capture files endianness.
    /// </summary>
    /// <param name="stream">The stream containing the packet capture bytes.</param>
    /// <returns>A binary reader for reading the .pcapng bytes.</returns>
    private BinaryReader GetBinaryReader(Stream stream)
    {
        var binaryReader = new BinaryReader(stream);
        var block = _blockFactory.ReadNextBlock(binaryReader, _frameNumber);

        if (block is SectionHeaderBlock sectionHeaderBlock)
        {
            if (sectionHeaderBlock.MagicNumber == MagicNumber.Identical)
            {
                return binaryReader;
            }

            if (sectionHeaderBlock.MagicNumber == MagicNumber.Swapped)
            {
                return new ReverseEndianBinaryReader(stream);
            }

            throw new InvalidOperationException("Could not parse magic number from section header block.");
        }

        throw new EndOfStreamException("No section header block present in stream.");
    }
}