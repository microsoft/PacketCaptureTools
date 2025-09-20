// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Physical;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP
{
    /// <summary>
    /// Network packet with IPv4 or IPv6 protocol.
    /// </summary>
    public abstract class IpPacket : NetworkPacket
    {
        /// <summary>
        /// Gets the protocol for the data portion of the IP datagram.
        /// </summary>
        public abstract IpProtocol IpProtocol { get; }

        /// <summary>
        /// Gets the physical layer ether type (IPv4 or IPv6).
        /// </summary>
        public abstract EtherType EtherType { get; }
    }
}
