// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;
using System;

namespace Microsoft.PacketCapture.Converter;

/// <summary>
/// Reader that returns a <see cref="CapturedPacket"/>.
/// </summary>
public interface IPacketReader : IDisposable
{
    /// <summary>
    /// Returns a boolean indicating whether the reader has another packet capture event. The reader
    /// advances past any events until it finds the first valid <see cref="CapturedPacket"/> event or
    /// reaches the end of the input.
    /// </summary>
    ///
    /// <returns>
    /// Guaranteed to return a valid <see cref="CapturedPacket"/> object or null if an end of the file has been reached.
    /// </returns>
    bool HasNext();

    /// <summary>
    /// Reads the next event from the reader and returns <see cref="CapturedPacket"/>.
    /// </summary>
    ///
    /// <returns>
    /// Returns the next event represented as <see cref="CapturedPacket"/>. If there are no valid packet capture
    /// events left advances to the end of the input and returns null.
    /// </returns>
    CapturedPacket? ReadNext();
}
