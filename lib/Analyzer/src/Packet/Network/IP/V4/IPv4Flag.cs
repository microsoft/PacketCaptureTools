// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4
{
    /// <summary>
    /// IPv4 fragmentation flags.
    /// </summary>
    public enum IPv4Flag
    {
        /// <summary>
        /// No flags set.
        /// </summary>
        None = 0x0,

        /// <summary>
        /// More Fragments.
        /// </summary>
        MF = 0x1,

        /// <summary>
        /// Don't Fragment.
        /// </summary>
        DF = 0x2,
    }
}
