// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders
{
    /// <summary>
    /// Virtual Router Redundancy Protocol extended header class.
    /// </summary>
    internal class Vrrp : IPv6ExtendedHeaderBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Vrrp" /> class.
        /// </summary>
        /// <param name="packetBytes">Packet bytes data to read extended header.</param>
        /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
        internal Vrrp(byte[] packetBytes, long packetStartPosition)
            : base(packetBytes, packetStartPosition, IPv6ExtendedHeaderType.IPv6NoNxt)
        {
        }

        /// <inheritdoc />
        protected override long GetTotalLength(byte[] packetBytes, long packetStartPosition)
        {
            var currentDataLength = packetBytes.Length - packetStartPosition;

            // Lets check whether there are enough bytes to calculate the correct length.
            if (currentDataLength < 4)
            {
                return currentDataLength;
            }

            var version = packetBytes[packetStartPosition] >> 4;
            long ipCount = packetBytes[packetStartPosition + 3];

            if (version == 2)
            {
                return (ipCount * 4) + 16;
            }

            if (version == 3)
            {
                return (ipCount * 14) + 8;
            }

            return currentDataLength;
        }
    }
}
