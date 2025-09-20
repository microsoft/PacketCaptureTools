// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.Common
{
    /// <summary>
    /// Packet hash algorithm.
    /// </summary>
    internal enum HashAlgorithm : byte
    {
        /// <summary>
        /// Two's complement algorithm.
        /// </summary>
        TwoSComplement = 0,

        /// <summary>
        /// XOR algorithm.
        /// </summary>
        Xor = 1,

        /// <summary>
        /// CRC32 algorithm.
        /// </summary>
        Crc32 = 2,

        /// <summary>
        /// MD5 algorithm.
        /// </summary>
        Md5 = 3,

        /// <summary>
        /// SHA1 algorithm.
        /// </summary>
        Sha1 = 4,

        /// <summary>
        /// Invalid algorithm.
        /// </summary>
        Invalid = 7,
    }
}
