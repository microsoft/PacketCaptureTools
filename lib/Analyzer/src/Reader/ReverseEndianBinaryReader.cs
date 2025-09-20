// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Buffers.Binary;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader;

/// <summary>
/// A <see cref="BinaryReader" /> with reversed integers
/// for streams of binary data with a different endianness.
/// </summary>
internal class ReverseEndianBinaryReader : BinaryReader
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReverseEndianBinaryReader" /> class.
    /// </summary>
    /// <param name="input">The stream of binary data.</param>
    public ReverseEndianBinaryReader(Stream input)
        : base(input)
    {
    }

    /// <inheritdoc />
    public override ushort ReadUInt16()
    {
        var data = base.ReadUInt16();
        return BinaryPrimitives.ReverseEndianness(data);
    }

    /// <inheritdoc />
    public override uint ReadUInt32()
    {
        var data = base.ReadUInt32();
        return BinaryPrimitives.ReverseEndianness(data);
    }

    /// <inheritdoc />
    public override int ReadInt32()
    {
        var data = base.ReadInt32();
        return BinaryPrimitives.ReverseEndianness(data);
    }

    /// <inheritdoc />
    public override ulong ReadUInt64()
    {
        var data = base.ReadUInt64();
        return BinaryPrimitives.ReverseEndianness(data);
    }

    /// <inheritdoc />
    public override long ReadInt64()
    {
        var data = base.ReadInt64();
        return BinaryPrimitives.ReverseEndianness(data);
    }
}
