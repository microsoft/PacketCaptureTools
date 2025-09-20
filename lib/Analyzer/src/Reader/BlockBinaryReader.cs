// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.IO;

namespace Microsoft.PacketCapture.Analyzer.Reader;

/// <summary>
/// Binary reader for packet capture block bytes.
/// </summary>
internal class BlockBinaryReader : BinaryReader
{
    private readonly BinaryReader _binaryReader;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlockBinaryReader" /> class.
    /// </summary>
    /// <param name="binaryReader">The binary reader containing block bytes.</param>
    /// <param name="totalBlockLength">The total length of the packet capture block in bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="binaryReader" /> cannot be null.</exception>
    public BlockBinaryReader(BinaryReader binaryReader, int totalBlockLength)
        : base(binaryReader.BaseStream)
    {
        _binaryReader = binaryReader ?? throw new ArgumentNullException(nameof(binaryReader));
        RemainingBlockLength = totalBlockLength;
    }

    /// <summary>
    /// Gets the remaining bytes in the packet capture block.
    /// </summary>
    public int RemainingBlockLength { get; private set; }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadUInt16" /> to return a ushort value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>A 2-byte unsigned integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '2' bytes left in the block.</exception>
    public override ushort ReadUInt16()
    {
        if (RemainingBlockLength >= sizeof(ushort))
        {
            RemainingBlockLength -= sizeof(ushort);
            return _binaryReader.ReadUInt16();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(UInt16)}' from reader, there is less than '{sizeof(ushort)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadInt16" /> to return a short value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>A 2-byte signed integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '2' bytes left in the block.</exception>
    public override short ReadInt16()
    {
        if (RemainingBlockLength >= sizeof(short))
        {
            RemainingBlockLength -= sizeof(short);
            return _binaryReader.ReadInt16();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(Int16)}' from reader, there is less than '{sizeof(short)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadUInt32" /> to return a uint value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>A 4-byte unsigned integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '4' bytes left in the block.</exception>
    public override uint ReadUInt32()
    {
        if (RemainingBlockLength >= sizeof(int))
        {
            RemainingBlockLength -= sizeof(int);
            return _binaryReader.ReadUInt32();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(UInt32)}' from reader, there is less than '{sizeof(uint)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadInt32" /> to return an int value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>A 4-byte signed integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '4' bytes left in the block.</exception>
    public override int ReadInt32()
    {
        if (RemainingBlockLength >= sizeof(int))
        {
            RemainingBlockLength -= sizeof(int);
            return _binaryReader.ReadInt32();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(Int32)}' from reader, there is less than '{sizeof(int)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadUInt64" /> to return a ulong value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>An 8-byte unsigned integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '8' bytes left in the block.</exception>
    public override ulong ReadUInt64()
    {
        if (RemainingBlockLength >= sizeof(ulong))
        {
            RemainingBlockLength -= sizeof(ulong);
            return _binaryReader.ReadUInt64();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(UInt64)}' from reader, there is less than '{sizeof(ulong)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadInt64" /> to return a long value, if there is enough bytes left in the block.
    /// </summary>
    /// <returns>An 8-byte signed integer from the block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than '8' bytes left in the block.</exception>
    public override long ReadInt64()
    {
        if (RemainingBlockLength >= sizeof(long))
        {
            RemainingBlockLength -= sizeof(long);
            return _binaryReader.ReadInt64();
        }

        throw new ArgumentOutOfRangeException($"Could not read '{nameof(Int64)}' from reader, there is less than '{sizeof(long)}' bytes in block.");
    }

    /// <summary>
    /// Using <see cref="BinaryReader.ReadBytes(int)" /> to return a byte array, if these is enough bytes left in the block.
    /// </summary>
    /// <param name="count">The number of bytes to read from packet capture block.</param>
    /// <returns>A byte array containing bytes from the packet capture block.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If there is less than <paramref name="count" /> bytes left in the block.</exception>
    public override byte[] ReadBytes(int count)
    {
        if (RemainingBlockLength >= count)
        {
            RemainingBlockLength -= count;
            return _binaryReader.ReadBytes(count);
        }

        throw new ArgumentOutOfRangeException($"Could not read '{count}' bytes from reader, there is less than '{RemainingBlockLength}' bytes in block.");
    }
}
