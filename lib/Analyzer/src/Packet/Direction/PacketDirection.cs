// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Direction
{
    /// <summary>
    /// Packet direction.
    /// </summary>
    public enum PacketDirection
    {
        /// <summary>
        /// Unknown direction
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Outgoing packet.
        /// </summary>
        Outgoing,

        /// <summary>
        /// Incoming packet.
        /// </summary>
        Incoming,
    }
}
