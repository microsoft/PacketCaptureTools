// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Packet;

namespace Microsoft.PacketCapture.Converter;

/// <summary>
/// Converter which takes generic <see cref="{TData}" /> and converts to intermediary <see cref="CapturedPacket"/> data structure.
/// </summary>
/// <typeparam name="TData">Type to convert to a CapturedPacket.</typeparam>
public interface ICapturedPacketAdapter<in TData>
{
    /// <summary>
    /// Converts data to a CapturedPacket.
    /// </summary>
    /// <param name="data">Data to be converted to CapturedPacket.</param>
    /// <returns>A valid CapturedPacket or null if the data cannot be converted.</returns>
    CapturedPacket? Convert(TData data);
}
