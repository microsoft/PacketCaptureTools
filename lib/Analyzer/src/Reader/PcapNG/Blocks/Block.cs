// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Blocks;

/// <summary>
/// Abstract PcapNG Block.
/// </summary>
internal abstract class Block
{
    /// <summary>
    /// Gets the block default size (without options).
    /// </summary>
    public abstract int DefaultSize { get; }

    /// <summary>
    /// Gets block Type.
    /// </summary>
    public abstract BlockType Type { get; }

    /// <summary>
    /// Gets the total block length.
    /// </summary>
    public abstract int TotalLength { get; }

    /// <summary>
    /// Gets information about relations between packet and interface on which it was captured.
    /// </summary>
    public abstract int? AssociatedInterfaceId { get; }
}
