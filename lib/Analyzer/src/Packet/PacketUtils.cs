// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet;

/// <summary>
/// Packet utils.
/// </summary>
internal static class PacketUtils
{
    /// <summary>
    /// The maximum number of bytes required for the headers of a ethernet frame (without the payload).
    /// </summary>
    public const int MaxPacketHeaderSize = 96;

    /// <summary>
    /// All fields of PcapNG specification use proper alignment for 16-bit and 32-bit values.
    /// This makes it easier and faster to read/write file contents if using techniques like memory mapped files.
    /// </summary>
    public const int PcapAlignmentBoundary = 4;

    /// <summary>
    /// Swap the first and last 4 bits positions.
    /// </summary>
    /// <param name="value">Binary value.</param>
    /// <returns>Binary value with swapped first and second nibbles.</returns>
    public static int SwapNibbles(int value)
    {
        return ((value & 0x0F) << 4) | ((value & 0xF0) >> 4);
    }

    /// <summary>
    /// Gets the total number of bytes needed to pad an array to 32-bits (4 bytes).
    /// </summary>
    /// <param name="payloadLength">The length of the packet payload.</param>
    /// <returns>Total number of bytes needed to pad the payload to 32-bits.</returns>
    public static int Get32BitPaddingAmount(int payloadLength)
    {
        return (PcapAlignmentBoundary - (payloadLength % PcapAlignmentBoundary)) % PcapAlignmentBoundary;
    }
}