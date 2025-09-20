// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes;
using System;
using System.IO;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;

/// <summary>
/// Enhanced packet block options.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EnhancedPacketOption" /> class.
/// </remarks>
/// <param name="binaryReader">Binary reader with enhanced packet header block option bytes.</param>
/// <param name="optionsBlockSize">The size of the options block in bytes.</param>
internal class EnhancedPacketOption(BinaryReader binaryReader, int optionsBlockSize) : Option(binaryReader, optionsBlockSize)
{

    /// <summary>
    /// Gets a UTF-8 string containing a comment that is associated to the current block.
    /// </summary>
    public string? Comment
    {
        get
        {
            var bytes = GetOption((ushort)EnhancedPacketOptionCode.CommentCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets packet flags containing link-layer information.
    /// </summary>
    public PacketBlockFlag? PacketFlag
    {
        get
        {
            var bytes = GetOption((ushort)EnhancedPacketOptionCode.PacketFlagCode);

            if (bytes == null ||
                bytes.Length != 4)
            {
                return null;
            }

            return new PacketBlockFlag(BitConverter.ToUInt32(bytes, 0));
        }
    }

    /// <summary>
    /// Gets an option containing a hash of the packet.
    /// </summary>
    public HashBlock? Hash
    {
        get
        {
            var bytes = GetOption((ushort)EnhancedPacketOptionCode.HashCode);

            if (bytes == null ||
                bytes.Length < 2)
            {
                return null;
            }

            return new HashBlock(bytes);
        }
    }

    /// <summary>
    /// Gets a 64-bit integer value specifying the number of packets lost (by the interface and the operating system) between this packet and the preceding one.
    /// </summary>
    public long? DropCount
    {
        get
        {
            var bytes = GetOption((ushort)EnhancedPacketOptionCode.DropCountCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }
}
