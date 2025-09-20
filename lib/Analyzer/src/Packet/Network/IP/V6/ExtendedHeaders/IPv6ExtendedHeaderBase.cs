// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders
{
    /// <summary>
    /// IPv6ExtendedHeaderBase class.
    /// </summary>
    internal abstract class IPv6ExtendedHeaderBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IPv6ExtendedHeaderBase" /> class.
        /// </summary>
        /// <param name="packetBytes">Packet bytes data to read extended header.</param>
        /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
        /// <param name="nextExtendedHeaderType">Extended header type of the next packet, if available and not present in the packet.</param>
        internal IPv6ExtendedHeaderBase(byte[] packetBytes, long packetStartPosition, IPv6ExtendedHeaderType? nextExtendedHeaderType = null)
        {
            if (nextExtendedHeaderType != null)
            {
                NextExtendedHeaderType = (IPv6ExtendedHeaderType)nextExtendedHeaderType;
            }
            else
            {
                int nextExtendedHeaderTypeValue = packetBytes[packetStartPosition];
                if (Enum.IsDefined(typeof(IPv6ExtendedHeaderType), nextExtendedHeaderTypeValue))
                {
                    NextExtendedHeaderType = (IPv6ExtendedHeaderType)nextExtendedHeaderTypeValue;
                }
            }

            ExtendedHeaderLengthInBytes = GetTotalLength(packetBytes, packetStartPosition);
        }

        /// <summary>
        /// Gets the next extended header type.
        /// </summary>
        public IPv6ExtendedHeaderType NextExtendedHeaderType { get; }

        /// <summary>
        /// Gets the length of extended header in bytes starting from header type byte to the end.
        /// </summary>
        public long ExtendedHeaderLengthInBytes { get; }

        /// <summary>
        /// Sets the length of the header. Every header has its own length calculation formula.
        /// </summary>
        /// <param name="packetBytes">Packet bytes data to read data.</param>
        /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
        /// <returns>Total length of the extended header in bytes.</returns>
        protected abstract long GetTotalLength(byte[] packetBytes, long packetStartPosition);
    }
}
