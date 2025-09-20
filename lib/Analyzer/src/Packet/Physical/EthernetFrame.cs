// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet.Network;
using System;
using System.Linq;
using System.Net.NetworkInformation;

namespace Microsoft.PacketCapture.Analyzer.Packet.Physical;

/// <summary>
/// Ethernet II frame.
/// </summary>
internal class EthernetFrame : PhysicalFrame
{
    private const int HeaderSize = 14;

    /// <summary>
    /// Initializes a new instance of the <see cref="EthernetFrame" /> class.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="originalPacketLength">The original packet length.</param>
    /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 14 bytes.</exception>
    public static EthernetFrame Parse(byte[] packetBytes, int originalPacketLength, PacketContentReader packetContentReader)
    {
        if (packetBytes.Length < 14)
        {
            throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 14 bytes.");
        }

        var destinationMacAddress = new PhysicalAddress(packetBytes.Take(6).ToArray());
        var sourceMacAddress = new PhysicalAddress(packetBytes.Skip(6).Take(6).ToArray());
        var etherType = GetEtherType((packetBytes[12] << 8) | packetBytes[13]);

        packetContentReader.TryGetNetworkPacket(
                packetBytes,
                HeaderSize,
                originalPacketLength - HeaderSize,
                etherType,
                out var networkPacket);

        return new EthernetFrame(destinationMacAddress, sourceMacAddress, etherType, networkPacket);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EthernetFrame" /> class.
    /// </summary>
    /// <param name="destinationMacAddress">The destination MAC address.</param>
    /// <param name="sourceMacAddress">The source MAC address.</param>
    /// <param name="etherType">The link layer ether type.</param>
    /// <param name="networkPacket">Optional. Encapsulated network packet.</param>
    internal EthernetFrame(PhysicalAddress destinationMacAddress, PhysicalAddress sourceMacAddress, EtherType etherType, NetworkPacket? networkPacket = null)
    {
        DestinationMacAddress = destinationMacAddress ?? throw new ArgumentNullException(nameof(destinationMacAddress));
        SourceMacAddress = sourceMacAddress ?? throw new ArgumentNullException(nameof(sourceMacAddress));
        EtherType = etherType;
        NetworkPacket = networkPacket;
    }

    /// <inheritdoc />
    public override PhysicalFrameProtocol Protocol => PhysicalFrameProtocol.ETH2;

    /// <inheritdoc />
    public override NetworkPacket? NetworkPacket { get; }

    /// <summary>
    /// Gets the destination mac address.
    /// </summary>
    public PhysicalAddress DestinationMacAddress { get; }

    /// <summary>
    /// Gets the source mac address.
    /// </summary>
    public PhysicalAddress SourceMacAddress { get; }

    /// <summary>
    /// Gets the ether type.
    /// </summary>
    public EtherType EtherType { get; }

    /// <summary>
    /// Get Ether type by value.
    /// </summary>
    /// <param name="value">Value of ether type.</param>
    /// <returns>Ethernet frame ether type.</returns>
    private static EtherType GetEtherType(int value)
    {
        if (Enum.IsDefined(typeof(EtherType), value))
        {
            return (EtherType)value;
        }

        return EtherType.Unsupported;
    }
}
