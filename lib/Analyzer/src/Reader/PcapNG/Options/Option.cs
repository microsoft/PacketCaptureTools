// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;

/// <summary>
/// Abstract option type.
/// </summary>
internal abstract class Option
{
    private const short EndOfOption = 0;
    private const short OptionSizeBytes = 4;

    /// <summary>
    /// Initializes a new instance of the <see cref="Option" /> class.
    /// </summary>
    /// <param name="binaryReader">Binary reader containing option bytes.</param>
    /// <param name="optionsBlockSize">The size of the options block in bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="binaryReader" /> cannot be null.</exception>
    public Option(BinaryReader binaryReader, int optionsBlockSize)
    {
        _ = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));

        if (optionsBlockSize < OptionSizeBytes)
        {
            throw new ArgumentOutOfRangeException($"'{nameof(optionsBlockSize)}' cannot be less than '{OptionSizeBytes}' bytes.");
        }

        var optionsResult = new Dictionary<ushort, byte[]>();

        while (optionsBlockSize >= OptionSizeBytes)
        {
            byte[] value;
            var optionCode = binaryReader.ReadUInt16();
            var valueLength = binaryReader.ReadUInt16();

            if (valueLength > 0)
            {
                value = binaryReader.ReadBytes(valueLength);
                if (value.Length < valueLength)
                {
                    throw new EndOfStreamException($"Unable to read beyond the end of the stream, option value length is set to '{valueLength}', actual length is '{value.Length}'.");
                }

                var remainderLength = valueLength % PacketUtils.PcapAlignmentBoundary;
                if (remainderLength > 0)
                {
                    binaryReader.ReadBytes(PacketUtils.PcapAlignmentBoundary - remainderLength);
                    optionsBlockSize -= PacketUtils.PcapAlignmentBoundary - remainderLength;
                }

                optionsBlockSize -= OptionSizeBytes + valueLength;
                optionsResult.Add(optionCode, value);
            }

            if (optionCode == EndOfOption)
            {
                break;
            }
        }

        Options = optionsResult;
    }

    /// <summary>
    /// Gets a dictionary of option codes and their values.
    /// </summary>
    public IReadOnlyDictionary<ushort, byte[]> Options { get; }

    /// <summary>
    /// Get option value by option code.
    /// </summary>
    /// <param name="optionCode">Option ushort code.</param>
    /// <returns>Option value in a byte sequence.</returns>
    public byte[]? GetOption(ushort optionCode)
    {
        if (Options.TryGetValue(optionCode, out var value))
        {
            return value;
        }

        return null;
    }
}
