// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP
{
    /// <summary>
    /// IP Packet Protocol.
    /// </summary>
    public enum IpProtocol
    {
        /// <summary>
        /// Internet Control Message Protocol.
        /// </summary>
        ICMP = 1,

        /// <summary>
        /// Internet Group Management Protocol.
        /// </summary>
        IGMP = 2,

        /// <summary>
        /// Transmission Control Protocol.
        /// </summary>
        TCP = 6,

        /// <summary>
        /// User Datagram Protocol.
        /// </summary>
        UDP = 17,

        /// <summary>
        /// IPv6 Encapsulation.
        /// </summary>
        ENCAP = 41,

        /// <summary>
        /// IPv6 ICMP.
        /// </summary>
        ICMPv6 = 58,

        /// <summary>
        /// For IPv6, Protocol is Not Applicable. The packet does not have any protocol.
        /// </summary>
        NA = 59,

        /// <summary>
        /// Open Shortest Path First.
        /// </summary>
        OSPF = 89,

        /// <summary>
        /// Protocol Independent Multicast.
        /// </summary>
        PIM = 103,

        /// <summary>
        /// Virtual Router Redundancy Protocol.
        /// </summary>
        VRRP = 112,

        /// <summary>
        /// Stream Control Transmission Protocol.
        /// </summary>
        SCTP = 132,
    }
}
