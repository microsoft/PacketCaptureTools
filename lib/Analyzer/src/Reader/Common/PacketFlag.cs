// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.Common
{
    /// <summary>
    /// Packet flags.
    /// </summary>
    internal enum PacketFlag : uint
    {
        /// <summary>
        /// Inbound packet.
        /// </summary>
        Inbound = 0x00000001,

        /// <summary>
        /// Outbound packet.
        /// </summary>
        Outbound = 0x00000002,

        /// <summary>
        /// Unicast packet.
        /// </summary>
        Unicast = 0x00000004,

        /// <summary>
        /// Multicast packet.
        /// </summary>
        Multicast = 0x00000008,

        /// <summary>
        /// Broadcast packet.
        /// </summary>
        Broadcast = 0x0000000C,

        /// <summary>
        /// Promiscuous packet.
        /// </summary>
        Promiscuous = 0x00000010,

        /// <summary>
        /// Packet frame check sequence length.
        /// </summary>
        FCSLength = 0x000001E0,

        /// <summary>
        /// Cyclic Redundancy Check error.
        /// </summary>
        CrcError = 0x01000000,

        /// <summary>
        /// Packet too long error.
        /// </summary>
        PacketTooLongError = 0x02000000,

        /// <summary>
        /// Packet too short error.
        /// </summary>
        PacketTooShortError = 0x04000000,

        /// <summary>
        /// Wrong inter-frame gap error.
        /// </summary>
        WrongInterFrameGapError = 0x08000000,

        /// <summary>
        /// Unaligned frame error.
        /// </summary>
        UnalignedFrameError = 0x10000000,

        /// <summary>
        /// Start frame delimiter error.
        /// </summary>
        StartFrameDelimiterError = 0x20000000,

        /// <summary>
        /// Preamble error.
        /// </summary>
        PreambleError = 0x40000000,

        /// <summary>
        /// Symbol error.
        /// </summary>
        SymbolError = 0x80000000,
    }
}
