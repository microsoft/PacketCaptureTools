// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.ARP;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.UDP;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.PacketCapture.Analyzer.Packet;

/// <summary>
/// A reader for getting different layers of the OSI model.
/// </summary>
/// <param name="configuration">The analysis configuration.</param>
internal class PacketContentReader(IAnalysisConfiguration configuration)
{
    private readonly ILogger? _logger = configuration.LoggerFactory?.CreateLogger<PacketContentReader>();

    /// <summary>
    /// Try get physical layer header from packet bytes sequence.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="originalPacketLength">The original packet length.</param>
    /// <param name="physicalFrame">Physical layer packet header.</param>
    /// <returns>True if <paramref name="packetBytes" /> contains a physical layer packet header; otherwise, false.</returns>
    public bool TryGetPhysicalFrame(byte[] packetBytes, int originalPacketLength, [NotNullWhen(true)] out PhysicalFrame? physicalFrame)
    {
        physicalFrame = null;

        try
        {
            physicalFrame = EthernetFrame.Parse(packetBytes, originalPacketLength, this);
            return true;
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Unable to create ethernet frame");
            return false;
        }
    }

    /// <summary>
    /// Try get network layer header from packet bytes sequence.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="ipPacketLength">The captured ip packet length.</param>
    /// <param name="etherType">Physical layer ether type.</param>
    /// <param name="header">Network layer packet header.</param>
    /// <returns>True if <paramref name="packetBytes" /> contains a network layer packet header; otherwise, false.</returns>
    public bool TryGetNetworkPacket(
        byte[] packetBytes,
        int packetStartPosition,
        int ipPacketLength,
        EtherType etherType,
        [NotNullWhen(true)] out NetworkPacket? header)
    {
        header = null;

        try
        {
            switch (etherType)
            {
                case EtherType.ARP:
                    header = ArpPacket.Parse(packetBytes, packetStartPosition);
                    return true;
                case EtherType.IPv4:
                    header = IPv4Packet.Parse(packetBytes, packetStartPosition, ipPacketLength, this);
                    return true;
                case EtherType.IPv6:
                    header = IPv6Packet.Parse(packetBytes, packetStartPosition, ipPacketLength, this);
                    return true;
                default:
                    _logger?.LogWarning("Unrecognized ether type: {EtherType}", etherType);
                    return false;
            }
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Unable to create network packet");
            return false;
        }
    }

    /// <summary>
    /// Try get transport layer header from packet bytes sequence.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="transportSegmentSize">Non-truncated transport segment size in bytes.</param>
    /// <param name="ipProtocol">IP protocol from network layer packet header.</param>
    /// <param name="header">Transport layer packet header.</param>
    /// <returns>True if <paramref name="packetBytes" /> contains a transport layer packet header; otherwise, false.</returns>
    public bool TryGetTransportSegment(
        byte[] packetBytes, 
        int packetStartPosition, 
        long transportSegmentSize, 
        IpProtocol ipProtocol, 
        [NotNullWhen(true)] out TransportSegment? header)
    {
        header = null;

        try
        {
            switch (ipProtocol)
            {
                case IpProtocol.TCP:
                    header = new TcpSegment(packetBytes, packetStartPosition, transportSegmentSize);
                    return true;
                case IpProtocol.UDP:
                    header = new UdpSegment(packetBytes, packetStartPosition);
                    return true;
                case IpProtocol.NA:
                    return false;
                default:
                    _logger?.LogWarning("Unrecognized IP Protocol: {IpProtocol}", ipProtocol);
                    return false;
            }
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Unable to create transport segment");
            return false;
        }
    }
}
