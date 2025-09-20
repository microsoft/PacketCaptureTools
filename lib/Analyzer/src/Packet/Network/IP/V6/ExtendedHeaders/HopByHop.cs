// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using System;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders
{
    /// <summary>
    /// IPv6 HopByHop extended header.
    /// </summary>
    internal class HopByHop : IPv6ExtendedHeaderBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HopByHop" /> class.
        /// </summary>
        /// <param name="packetBytes">Packet bytes data to read extended header.</param>
        /// <param name="packetStartPosition">Start byte position of the extended header in the packet.</param>
        /// <exception cref="Exception">If an undefined hop by hop option exists.</exception>
        internal HopByHop(byte[] packetBytes, long packetStartPosition)
            : base(packetBytes, packetStartPosition)
        {
            var currentReadPosition = packetStartPosition + 2;
            while (currentReadPosition - packetStartPosition < ExtendedHeaderLengthInBytes)
            {
                int headerOptionValue = packetBytes[currentReadPosition++];
                var hopByHopOption = EnumExtensions.GetEnumValue<IPv6ExtendedHeaderOption>(headerOptionValue, $"Invalid/unrecognized IPv6 extended header option: '{headerOptionValue}'");

                switch (hopByHopOption)
                {
                    case IPv6ExtendedHeaderOption.Pad1:
                        break;

                    case IPv6ExtendedHeaderOption.PadN:
                        int padCount = packetBytes[currentReadPosition++];
                        currentReadPosition += padCount;
                        break;

                    case IPv6ExtendedHeaderOption.RouterAlert:
                        currentReadPosition += 3;
                        break;

                    case IPv6ExtendedHeaderOption.JumboPayload:
                        currentReadPosition++;
                        JumboPayloadLength = (packetBytes[currentReadPosition++] << 24) | (packetBytes[currentReadPosition++] << 16) | (packetBytes[currentReadPosition++] << 8) | packetBytes[currentReadPosition++];
                        break;

                    default: throw new Exception($"Invalid/unrecognized IPv6 hop by hop option: '{hopByHopOption}'");
                }
            }
        }

        /// <summary>
        /// Gets the ayload length of the IPv6 packet.
        /// </summary>
        public long JumboPayloadLength { get; }

        /// <inheritdoc />
        protected override long GetTotalLength(byte[] packetBytes, long packetStartPosition)
        {
            return (packetBytes[packetStartPosition + 1] + 1) * 8;
        }
    }
}
