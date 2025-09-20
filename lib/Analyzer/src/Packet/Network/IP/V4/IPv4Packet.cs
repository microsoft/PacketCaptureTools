// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;
using System.Linq;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4;

/// <summary>
/// IPv4 Protocol Packet.
/// </summary>
internal class IPv4Packet : IpPacket
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IPv4Packet" /> class.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <param name="ipPacketLength">The captured ip packet length.</param>
    /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 20 bytes.</exception>
    public static IPv4Packet Parse(byte[] packetBytes, int packetStartPosition, int ipPacketLength, PacketContentReader packetContentReader)
    {
        if (packetBytes.Length < packetStartPosition + 20)
        {
            throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 20 bytes.");
        }

        var version = packetBytes[packetStartPosition + 0] >> 4;
        var headerLengthInWords = packetBytes[packetStartPosition + 0] & 0x0f;

        var dscpValueInt = packetBytes[packetStartPosition + 1] >> 2;
        var dscpValue = EnumExtensions.GetEnumValueOrDefault(dscpValueInt, DscpValue.Unrecognised);

        var totalLength = (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3];
        var identification = (packetBytes[packetStartPosition + 4] << 8) | packetBytes[packetStartPosition + 5];

        var ipv4FlagValue = packetBytes[packetStartPosition + 6] >> 5;
        var flags = EnumExtensions.GetEnumValue<IPv4Flag>(ipv4FlagValue, $"Invalid/unrecognized IPv4 flag: '{ipv4FlagValue}'");
        var fragmentOffset = ((packetBytes[packetStartPosition + 6] & 0x1F) << 8) | packetBytes[packetStartPosition + 7];
        var timeToLive = packetBytes[packetStartPosition + 8];

        int ipProtocolValue = packetBytes[packetStartPosition + 9];
        var ipProtocol = EnumExtensions.GetEnumValue<IpProtocol>(ipProtocolValue, $"Invalid/unrecognized IPv4 protocol type: '{ipProtocolValue}'");

        var sourceAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 12).Take(4).ToArray());
        var destinationAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 16).Take(4).ToArray());

        int headerSize = 20;

        if (headerLengthInWords > 5)
        {
            headerSize = headerLengthInWords * 4;
        }

        if (totalLength < headerSize ||
            totalLength == 0)
        {
            totalLength = ipPacketLength;
        }

        packetContentReader.TryGetTransportSegment(
                packetBytes: packetBytes,
                packetStartPosition: packetStartPosition + headerSize,
                transportSegmentSize: totalLength - headerSize,
                ipProtocol: ipProtocol,
                header: out var transportSegment);

        return new IPv4Packet(version,
                              headerLengthInWords,
                              dscpValue,
                              totalLength,
                              identification,
                              flags,
                              fragmentOffset,
                              timeToLive,
                              ipProtocol,
                              sourceAddress,
                              destinationAddress,
                              transportSegment);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IPv4Packet" /> class.
    /// </summary>
    /// <param name="version">The IP version.</param>
    /// <param name="headerLengthInWords">The header length.</param>
    /// <param name="dscpValue">The packet Dscp value.</param>
    /// <param name="totalLength">The packet total length.</param>
    /// <param name="identification">The identification field of the packet.</param>
    /// <param name="flags">IPv4 flags.</param>
    /// <param name="fragmentOffset">The packet fragment offset.</param>
    /// <param name="timeToLive">Time to live number.</param>
    /// <param name="ipProtocol">The transport layer protocol.</param>
    /// <param name="sourceAddress">The source address.</param>
    /// <param name="destinationAddress">The target address.</param>
    /// <param name="transportSegment">Optional. The transport layer segment.</param>
    internal IPv4Packet(
        int version,
        int headerLengthInWords,
        DscpValue dscpValue,
        int totalLength,
        long identification,
        IPv4Flag flags,
        int fragmentOffset,
        int timeToLive,
        IpProtocol ipProtocol,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        TransportSegment? transportSegment = null)
    {
        SourceAddress = sourceAddress ?? throw new ArgumentNullException(nameof(sourceAddress));
        DestinationAddress = destinationAddress ?? throw new ArgumentNullException(nameof(destinationAddress));

        Version = version;
        HeaderLengthInWords = headerLengthInWords;
        DscpValue = dscpValue;
        TotalLength = totalLength;
        Identification = identification;
        Flags = flags;
        FragmentOffset = fragmentOffset;
        TimeToLive = timeToLive;
        IpProtocol = ipProtocol;
        TransportSegment = transportSegment;
    }

    /// <inheritdoc />
    public override NetworkPacketProtocol Protocol => NetworkPacketProtocol.IPv4;

    /// <summary>
    /// Gets the ethernet network layer packet, if transport layer protocol is unsupported or is not present then returns null.
    /// </summary>
    public override TransportSegment? TransportSegment { get; }

    /// <summary>
    /// Gets the IP Version (always 4).
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the packet header length in 32-bit words.
    /// </summary>
    public int HeaderLengthInWords { get; }

    /// <summary>
    /// Gets the packet header length in bytes.
    /// </summary>
    public int HeaderLength => HeaderLengthInWords * 4;

    /// <summary>
    /// Gets the packet Dscp value.
    /// </summary>
    public DscpValue DscpValue { get; }

    /// <summary>
    /// Gets the total packet length in bytes.
    /// </summary>
    public int TotalLength { get; }

    /// <summary>
    /// Gets the identification for uniquely identifying the group of fragments of a single IP datagram.
    /// </summary>
    public long Identification { get; }

    /// <summary>
    /// Gets the three-bit field follows and is used to control or identify fragments.
    /// </summary>
    public IPv4Flag Flags { get; }

    /// <summary>
    /// Gets the field which specifies the offset of a particular fragment relative to the beginning of the original
    /// unfragmented IP datagram in units of eight-byte blocks.
    /// </summary>
    public int FragmentOffset { get; }

    /// <summary>
    /// Gets the packet time to live in number of hops.
    /// </summary>
    public int TimeToLive { get; }

    /// <summary>
    /// Gets the protocol for the data portion of the IP datagram.
    /// </summary>
    public override IpProtocol IpProtocol { get; }

    /// <summary>
    /// Gets the senders IP address.
    /// </summary>
    public override IPAddress SourceAddress { get; }

    /// <summary>
    /// Gets the receiver IP address.
    /// </summary>
    public override IPAddress DestinationAddress { get; }

    /// <inheritdoc />
    public override EtherType EtherType => EtherType.IPv4;

    /// <summary>
    /// Gets the payload length in bytes.
    /// </summary>
    public int PayloadLength => TotalLength - HeaderLength;
}
