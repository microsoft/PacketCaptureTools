// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using System;

namespace Microsoft.PacketCapture.Analyzer.Reader;

/// <summary>
/// Packet capture reader.
/// </summary>
public interface IReader : IDisposable
{
    /// <summary>
    /// Reads the next packet.
    /// </summary>
    /// <returns>The next packet. Returns <c>null</c> when there is no more packets to be read.</returns>
    CapturedPacket? ReadNext();

    /// <summary>
    /// Indicates whether there is another packet available to be read.
    /// </summary>
    /// <returns>True if there is another packet available, False if there is no more packets.</returns>
    bool HasNext();
}
