// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Packet.Transport.UDP
{
    /// <summary>
    /// User Datagram Protocol segment.
    /// </summary>
    public class UdpSegment : TransportSegment
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UdpSegment" /> class.
        /// </summary>
        /// <param name="packetBytes">The packet header as a byte sequence.</param>
        /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
        /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 8 bytes.</exception>
        public UdpSegment(byte[] packetBytes, int packetStartPosition)
        {
            if (packetBytes.Length < 8)
            {
                throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 8 bytes.");
            }

            SourcePort = (packetBytes[packetStartPosition + 0] << 8) | packetBytes[packetStartPosition + 1];
            DestinationPort = (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3];
            Length = (packetBytes[packetStartPosition + 4] << 8) | packetBytes[packetStartPosition + 5];
            Checksum = (packetBytes[packetStartPosition + 6] << 8) | packetBytes[packetStartPosition + 7];
            Payload = packetBytes.Skip(packetStartPosition + 8).ToArray();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UdpSegment" /> class.
        /// </summary>
        /// <param name="sourcePort">The source port.</param>
        /// <param name="destinationPort">The destination port.</param>
        /// <param name="length">The datagram length.</param>
        /// <param name="checksum">The segment checksum.</param>
        /// <param name="payload">The segment payload.</param>
        public UdpSegment(int sourcePort, int destinationPort, int length, int checksum, byte[] payload)
        {
            SourcePort = sourcePort;
            DestinationPort = destinationPort;
            Length = length;
            Checksum = checksum;
            Payload = payload;
        }

        /// <inheritdoc />
        public override TransportSegmentProtocol Protocol => TransportSegmentProtocol.UDP;

        /// <inheritdoc />
        public override byte[] Payload { get; }

        /// <inheritdoc />
        public override int SourcePort { get; }

        /// <inheritdoc />
        public override int DestinationPort { get; }

        /// <summary>
        /// Gets the length of the udp segment.
        /// </summary>
        public int Length { get; }

        /// <summary>
        /// Gets the udp segment checksum.
        /// </summary>
        public int Checksum { get; }
    }
}
