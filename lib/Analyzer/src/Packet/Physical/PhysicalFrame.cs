// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Network;

namespace Microsoft.PacketCapture.Analyzer.Packet.Physical;

/// <summary>
/// A physical network frame.
/// </summary>
public abstract class PhysicalFrame
{
    /// <summary>
    /// Gets the packet header type.
    /// </summary>
    public virtual PhysicalFrameProtocol Protocol { get; }

    /// <summary>
    /// Gets the network packet that the frame contains.Can be <c>null</c> when the network protocol data is unrecognized or not present
    /// </summary>
    public virtual NetworkPacket? NetworkPacket { get; }
}
