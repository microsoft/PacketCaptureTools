// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.Common
{
    /// <summary>
    /// Unsigned magic numbers whose order identifies what the endian type of the system that captured the traffic was.
    /// </summary>
    internal enum MagicNumber : uint
    {
        /// <summary>
        /// The same endian type.
        /// </summary>
        Identical = 0x1a2b3c4d,

        /// <summary>
        /// A different endian type.
        /// </summary>
        Swapped = 0x4d3c2b1a,
    }
}
