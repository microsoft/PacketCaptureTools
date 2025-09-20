// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks
{
    /// <summary>
    /// A block with capture packet data.
    /// </summary>
    internal interface IPacketBlock
    {
        /// <summary>
        /// Gets the capture packet data from the packet block.
        /// </summary>
        CapturedPacket CapturedPacket { get; }
    }
}
