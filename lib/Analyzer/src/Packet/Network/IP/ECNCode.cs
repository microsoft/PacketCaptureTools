// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP
{
    /// <summary>
    /// Explicit Congestion Notification operation codes.
    /// </summary>
    public enum EcnCode
    {
        /// <summary>
        /// Non-ECN capable transport.
        /// </summary>
        NonEct = 0b00,

        /// <summary>
        /// ECN capable transport (0).
        /// </summary>
        EctCapable_0 = 0b10,

        /// <summary>
        /// ECN capable transport (1).
        /// </summary>
        EctCapable_1 = 0b01,

        /// <summary>
        /// Congestion Encountered.
        /// </summary>
        CE = 0b11,
    }
}
