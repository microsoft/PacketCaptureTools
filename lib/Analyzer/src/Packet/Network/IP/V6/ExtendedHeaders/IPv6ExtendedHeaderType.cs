// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders
{
    /// <summary>
    /// IPv6 Extension Header Type for known types.
    /// </summary>
    public enum IPv6ExtendedHeaderType
    {
        /// <summary>
        /// Extended Header Type Hop By Hop.
        /// </summary>
        HopByHop = 0,

        /// <summary>
        /// Upper Layer Internet Control Message Protocol.
        /// </summary>
        ICMP = 1,

        /// <summary>
        /// Upper Layer Internet Group Management Protocol.
        /// </summary>
        IGMP = 2,

        /// <summary>
        /// Upper Layer Transmission Control Protocol.
        /// </summary>
        TCP = 6,

        /// <summary>
        /// Upper Layer User Datagram Protocol.
        /// </summary>
        UDP = 17,

        /// <summary>
        /// Upper Layer IPv6 Encapsulation.
        /// </summary>
        ENCAP = 41,

        /// <summary>
        /// Upper Layer IPv6 ICMP.
        /// </summary>
        ICMPv6 = 58,

        /// <summary>
        /// For IPv6, No Next Extended Header. The packet does not have any protocol.
        /// </summary>
        IPv6NoNxt = 59,

        /// <summary>
        /// Upper Layer Open Shortest Path First.
        /// </summary>
        OSPF = 89,

        /// <summary>
        /// Extended header type Virtual Router Redundancy Protocol.
        /// </summary>
        VRRP = 112,

        /// <summary>
        /// Upper Layer Stream Control Transmission Protocol.
        /// </summary>
        SCTP = 132,
    }
}
