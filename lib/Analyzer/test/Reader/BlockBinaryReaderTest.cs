// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader;
using System;
using System.IO;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader;

public class BlockBinaryReaderTest
{
    [Fact]
    public void Test_BlockBinaryReader_ReadUInt16()
    {
        ushort blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 2);
                blockBinaryReaderResult = blockBinaryReader.ReadUInt16();

                Assert.Equal(513, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadUInt16());
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadUInt16());
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_ReadInt16()
    {
        short blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 2);
                blockBinaryReaderResult = blockBinaryReader.ReadInt16();

                Assert.Equal(513, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadInt16());
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadInt16());
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_ReadUInt32()
    {
        uint blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 4);
                blockBinaryReaderResult = blockBinaryReader.ReadUInt32();

                Assert.Equal((decimal)67305985, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadUInt32());
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadUInt32());
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_ReadInt32()
    {
        int blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 4);
                blockBinaryReaderResult = blockBinaryReader.ReadInt32();

                Assert.Equal(67305985, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadInt32());
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadInt32());
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_ReadUInt64()
    {
        ulong blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 8);
                blockBinaryReaderResult = blockBinaryReader.ReadUInt64();

                Assert.Equal((decimal)578437695752307201, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadUInt64());
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadUInt64());
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_ReadBytes()
    {
        byte[] blockBinaryReaderResult;
        byte[] byteArray = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        byte[] expectedResult = { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                var blockBinaryReader = new BlockBinaryReader(binaryReader, totalBlockLength: 8);
                blockBinaryReaderResult = blockBinaryReader.ReadBytes(8);

                Assert.Equal(expectedResult, blockBinaryReaderResult);

                Assert.Throws<ArgumentOutOfRangeException>(() => blockBinaryReader.ReadBytes(8));
            }
        }

        using (var stream = new MemoryStream(byteArray))
        {
            using (var binaryReader = new BinaryReader(stream))
            {
                Assert.Equal(blockBinaryReaderResult, binaryReader.ReadBytes(8));
            }
        }
    }

    [Fact]
    public void Test_BlockBinaryReader_Null_Parameters()
    {
        Assert.Throws<NullReferenceException>(() => new BlockBinaryReader(null!, totalBlockLength: 0));
    }
}