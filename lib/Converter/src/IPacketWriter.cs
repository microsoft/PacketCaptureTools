// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;
using System;

namespace Microsoft.PacketCapture.Converter;

/// <summary>
/// <see cref="CapturedPacket"/> writer that receives packets and writes them to an output.
/// </summary>
public interface IPacketWriter : IDisposable
{
    /// <summary>
    /// Writes a packet to a destination.
    /// </summary>
    /// <param name="packet">A <see cref="CapturedPacket"/> to write.</param>
    void WritePacket(CapturedPacket packet);
}
