// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network
{
    /// <summary>
    /// Network packet protocol.
    /// </summary>
    public enum NetworkPacketProtocol
    {
        /// <summary>
        /// Internet Protocol Version 4.
        /// </summary>
        IPv4,

        /// <summary>
        /// Internet Protocol Version 6.
        /// </summary>
        IPv6,

        /// <summary>
        /// Address Resolution Protocol.
        /// </summary>
        ARP,
    }
}
