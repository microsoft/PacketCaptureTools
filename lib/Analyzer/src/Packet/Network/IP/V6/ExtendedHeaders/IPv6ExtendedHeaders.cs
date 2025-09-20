// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders;

/// <summary>
/// IPv6ExtendedHeaders class.
/// </summary>
internal class IPv6ExtendedHeaders
{
    private readonly bool _readFirstsExtendedHeader;
    private readonly List<IPv6ExtendedHeaderBase> _extendedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="IPv6ExtendedHeaders" /> class.
    /// </summary>
    /// <param name="packetBytes">Packet bytes data to read extended header.</param>
    /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
    /// <param name="firstExtendedHeaderType">Type of first extended header in the packet.</param>
    /// <param name="payloadLength">Payload length of the packet read from the upper layer.</param>
    internal IPv6ExtendedHeaders(byte[] packetBytes, long packetStartPosition, int firstExtendedHeaderType, long payloadLength)
    {
        PayloadLength = payloadLength;
        _extendedHeaders = new List<IPv6ExtendedHeaderBase>();

        if (!Enum.IsDefined(typeof(IPv6ExtendedHeaderType), firstExtendedHeaderType))
        {
            return;
        }

        var currentExtendedHeaderType = (IPv6ExtendedHeaderType)firstExtendedHeaderType;
        var currentReadPosition = packetStartPosition;

        while (!Enum.IsDefined(typeof(IpProtocol), (int)currentExtendedHeaderType))
        {
            var nextExtendedHeader = ReadNextExtendedHeader(packetBytes, currentReadPosition, currentExtendedHeaderType);

            if (nextExtendedHeader == null)
            {
                break;
            }

            _extendedHeaders.Add(nextExtendedHeader);
            _readFirstsExtendedHeader = true;
            currentExtendedHeaderType = nextExtendedHeader.NextExtendedHeaderType;
            currentReadPosition += nextExtendedHeader.ExtendedHeaderLengthInBytes;
        }

        ExtendedHeaderSize = currentReadPosition - packetStartPosition;

        if (Enum.IsDefined(typeof(IpProtocol), (int)currentExtendedHeaderType))
        {
            IpProtocol = (IpProtocol)currentExtendedHeaderType;
        }
    }

    /// <summary>
    /// Gets the total packet length in bytes.
    /// </summary>
    public long PayloadLength { get; private set; }

    /// <summary>
    /// Gets the length of extended headers in bytes in the payload.
    /// </summary>
    public long ExtendedHeaderSize { get; }

    /// <summary>
    /// Gets the Ip protocol of the IPv6 packet, which is set int the last extended header.
    /// </summary>
    public IpProtocol IpProtocol { get; }

    /// <summary>
    /// Read next extended header in the extended headers chain with the given type.
    /// </summary>
    /// <param name="packetBytes">Packet bytes data to read extended header.</param>
    /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
    /// <param name="extendedHeaderType">Type of the extended header.</param>
    /// <returns>Read extended header. 'null' if the extended header is not recognized.</returns>
    /// <exception cref="Exception">If the hop by hop extended header exists and it is not the first extended header.</exception>
    public IPv6ExtendedHeaderBase? ReadNextExtendedHeader(byte[] packetBytes, long packetStartPosition, IPv6ExtendedHeaderType extendedHeaderType)
    {
        switch (extendedHeaderType)
        {
            case IPv6ExtendedHeaderType.HopByHop:
                if (_readFirstsExtendedHeader)
                {
                    throw new Exception("Hop by hop extended header must be the first IPv6 extended header.");
                }

                var hopByHopExtendedHeader = new HopByHop(packetBytes, packetStartPosition);
                if (hopByHopExtendedHeader.JumboPayloadLength > 0)
                {
                    PayloadLength = hopByHopExtendedHeader.JumboPayloadLength;
                }

                return hopByHopExtendedHeader;
            case IPv6ExtendedHeaderType.VRRP:
                return new Vrrp(packetBytes, packetStartPosition);
            default:
                return null;
        }
    }
}
