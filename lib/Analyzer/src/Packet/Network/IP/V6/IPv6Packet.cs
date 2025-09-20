// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using System;
using System.Linq;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6
{
    /// <summary>
    /// IPv6 Protocol Packet.
    /// </summary>
    internal class IPv6Packet : IpPacket
    {
        private const int HeaderSize = 40;

        /// <summary>
        /// Initializes a new instance of the <see cref="IPv6Packet" /> class.
        /// </summary>
        /// <param name="packetBytes">The packet header as a byte sequence.</param>
        /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
        /// <param name="ipPacketLength">The captured ip packet length.</param>
        /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 40 bytes.</exception>
        public static IPv6Packet Parse(byte[] packetBytes, int packetStartPosition, int ipPacketLength, PacketContentReader packetContentReader)
        {
            if (packetBytes.Length < packetStartPosition + HeaderSize)
            {
                throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 40 bytes.");
            }

            var version = packetBytes[packetStartPosition] >> 4;

            var trafficClassValue = ((packetBytes[packetStartPosition] << 8) | (packetBytes[packetStartPosition + 1] >> 4)) & 0xff;
            var trafficClass = GetDscpValue(trafficClassValue);

            var ecnCode = EnumExtensions.GetEnumValue<EcnCode>(trafficClassValue, $"Invalid/unrecognized IP ECN code: '{trafficClassValue}'");
            var flowLabel = ((packetBytes[packetStartPosition + 1] << 16) | (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3]) & 0xfffff;
            long payloadLength = (packetBytes[packetStartPosition + 4] << 8) | packetBytes[packetStartPosition + 5];

            int ipProtocolValue = packetBytes[packetStartPosition + 6];
            long extendedHeadersSize = 0;

            IpProtocol ipProtocol = default;
            if (Enum.IsDefined(typeof(IpProtocol), ipProtocolValue))
            {
                ipProtocol = (IpProtocol)ipProtocolValue;
            }
            else
            {
                var extendedHeaders = new IPv6ExtendedHeaders(packetBytes, packetStartPosition + HeaderSize, ipProtocolValue, payloadLength);
                ipProtocol = extendedHeaders.IpProtocol;
                payloadLength = extendedHeaders.PayloadLength;
                extendedHeadersSize = extendedHeaders.ExtendedHeaderSize;
            }

            var hopLimit = packetBytes[packetStartPosition + 7];

            var sourceAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 8).Take(16).ToArray());
            var destinationAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 24).Take(16).ToArray());

            if (payloadLength == 0)
            {
                payloadLength = ipPacketLength - HeaderSize - extendedHeadersSize;

                if (payloadLength < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(PayloadLength), "Payload length cannot be a negative value.");
                }
            }

            var transportSegmentPacketStartPosition = packetStartPosition + HeaderSize + extendedHeadersSize;

            if (transportSegmentPacketStartPosition > int.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(transportSegmentPacketStartPosition), "Transport segment packet staring position length cannot be a greater than max int size.");
            }

            packetContentReader.TryGetTransportSegment(
                    packetBytes: packetBytes,
                    packetStartPosition: (int)transportSegmentPacketStartPosition,
                    transportSegmentSize: payloadLength,
                    ipProtocol: ipProtocol,
                    header: out var transportHeader);

            return new IPv6Packet(
                version: version,
                trafficClass: trafficClass,
                ecnCode: ecnCode,
                flowLabel: flowLabel,
                payloadLength: payloadLength,
                ipProtocol: ipProtocol,
                hopLimit: hopLimit,
                sourceAddress: sourceAddress,
                destinationAddress: destinationAddress,
                transportSegment: transportHeader);
        }

        private static DscpValue GetDscpValue(int dscpHex)
        {
            if ((dscpHex & (ushort)DscpValue.CS1) == 0)
            {
                return DscpValue.DF;
            }

            return EnumExtensions.GetEnumValueOrDefault(dscpHex, DscpValue.Unrecognised);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IPv6Packet" /> class.
        /// </summary>
        /// <param name="version">The IP version.</param>
        /// <param name="trafficClass">The IPv6 traffic class.</param>
        /// <param name="ecnCode">The ECN flag value.</param>
        /// <param name="flowLabel">The packet flow label.</param>
        /// <param name="payloadLength">The packet payload length.</param>
        /// <param name="ipProtocol">The transport segment protocol.</param>
        /// <param name="hopLimit">The packet hop limit (time to live).</param>
        /// <param name="sourceAddress">The source IP address.</param>
        /// <param name="destinationAddress">The taret IP address.</param>
        /// <param name="transportSegment">Optional. The transport segment.</param>
        internal IPv6Packet(
            int version,
            DscpValue trafficClass,
            EcnCode ecnCode,
            long flowLabel,
            long payloadLength,
            IpProtocol ipProtocol,
            int hopLimit,
            IPAddress sourceAddress,
            IPAddress destinationAddress,
            TransportSegment? transportSegment = null)
        {
            Version = version;
            TrafficClass = trafficClass;
            EcnCode = ecnCode;
            FlowLabel = flowLabel;
            PayloadLength = payloadLength;
            IpProtocol = ipProtocol;
            HopLimit = hopLimit;
            SourceAddress = sourceAddress ?? throw new ArgumentNullException(nameof(sourceAddress));
            DestinationAddress = destinationAddress ?? throw new ArgumentNullException(nameof(destinationAddress));
            TransportSegment = transportSegment;
        }

        /// <inheritdoc />
        public override NetworkPacketProtocol Protocol => NetworkPacketProtocol.IPv6;

        /// <summary>
        /// Gets the ethernet network layer packet, if transport layer protocol is unsupported or is not present then returns null.
        /// </summary>
        public override TransportSegment? TransportSegment { get; }

        /// <summary>
        /// Gets the senders IP address.
        /// </summary>
        public override IPAddress SourceAddress { get; }

        /// <summary>
        /// Gets the receiver IP address.
        /// </summary>
        public override IPAddress DestinationAddress { get; }

        /// <inheritdoc />
        public override EtherType EtherType => EtherType.IPv6;

        /// <summary>
        /// Gets the protocol for the data portion of the IP datagram.
        /// </summary>
        public override IpProtocol IpProtocol { get; }

        /// <summary>
        /// Gets the IP Version (always 6).
        /// </summary>
        public int Version { get; }

        /// <summary>
        /// Gets the total packet length in bytes.
        /// </summary>
        public long PayloadLength { get; }

        /// <summary>
        /// Gets the packet time to live in number of hops.
        /// </summary>
        public int HopLimit { get; }

        /// <summary>
        /// Gets the value of the IPv6 traffic class.
        /// </summary>
        public DscpValue TrafficClass { get; }

        /// <summary>
        /// Gets the value for the ECN flag.
        /// </summary>
        public EcnCode EcnCode { get; }

        /// <summary>
        /// Gets the value of the IPv6 flow label.
        /// </summary>
        public long FlowLabel { get; }
    }
}
