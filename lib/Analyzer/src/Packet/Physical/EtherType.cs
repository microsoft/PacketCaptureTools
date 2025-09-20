// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Physical
{
    /// <summary>
    /// Ethernet type.
    /// </summary>
    public enum EtherType
    {
        /// <summary>
        /// Unsupported Ethertype.
        /// </summary>
        Unsupported = 0,

        /// <summary>
        /// IPv4 EtherType.
        /// </summary>
        IPv4 = 0x0800,

        /// <summary>
        /// IPv6 EtherType.
        /// </summary>
        IPv6 = 0x86DD,

        /// <summary>
        /// ARP EtherType.
        /// </summary>
        ARP = 0x0806,

        /// <summary>
        /// Link Layer Discovery Protocol.
        /// </summary>
        LLDP = 0x88CC,
    }
}
