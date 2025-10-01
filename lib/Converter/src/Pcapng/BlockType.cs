// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Converter.Pcapng;

/// <summary>
/// Base Block Types from Pcapng file format.
/// </summary>
internal enum BlockType : uint
{
    /// <summary>
    /// Section Header Block Identifier.
    /// </summary>
    SectionHeader = 0x0A0D0D0A,

    /// <summary>
    /// Interface Description Block Identifier.
    /// </summary>
    InterfaceDescription = 0x00000001,

    /// <summary>
    /// Packet Block Identifier.
    /// </summary>
    Packet = 0x00000002,

    /// <summary>
    /// Simple Packet Block Identifier.
    /// </summary>
    SimplePacket = 0x00000003,

    /// <summary>
    /// Interface Statistics Block Identifier.
    /// </summary>
    InterfaceStatistics = 0x00000005,

    /// <summary>
    /// Enhanced Packet Block Identifier.
    /// </summary>
    EnhancedPacket = 0x00000006,
}