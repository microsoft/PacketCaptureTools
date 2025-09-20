// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.ARP;

/// <summary>
/// Address Resolution Protocol packet.
/// </summary>
public class ArpPacket : NetworkPacket
{
    /// <summary>
    /// Parses a new instance of the <see cref="ArpPacket" /> from a byte array.
    /// </summary>
    /// <param name="packetBytes">The packet header as a byte sequence.</param>
    /// <param name="packetStartPosition">Starting position in <paramref name="packetBytes" /> to begin parsing from.</param>
    /// <exception cref="ArgumentException"><paramref name="packetBytes" /> can't be less than 28 bytes.</exception>
    public static ArpPacket Parse(byte[] packetBytes, int packetStartPosition)
    {
        if (packetBytes.Length < packetStartPosition + 28)
        {
            throw new ArgumentException($"'{nameof(packetBytes)}' can't be less than 28 bytes.");
        }

        var hardwareTypeValue = (packetBytes[packetStartPosition] << 8) | packetBytes[packetStartPosition + 1];
        var hardwareType = EnumExtensions.GetEnumValue<HardwareType>(hardwareTypeValue, $"Invalid/unrecognized ARP hardware type: '{hardwareTypeValue}'");

        var etherTypeValue = (packetBytes[packetStartPosition + 2] << 8) | packetBytes[packetStartPosition + 3];
        var EtherType = EnumExtensions.GetEnumValue<EtherType>(etherTypeValue, $"Invalid/unrecognized EtherType: '{etherTypeValue}'");
        var HardwareAddressLength = packetBytes[packetStartPosition + 4];
        var ProtocolAddressLength = packetBytes[packetStartPosition + 5];

        var operationCodeValue = (packetBytes[packetStartPosition + 6] << 8) | packetBytes[packetStartPosition + 7];
        var OperationCode = EnumExtensions.GetEnumValue<OperationCode>(operationCodeValue, $"Invalid/unrecognized ARP operation code: '{operationCodeValue}'");

        PhysicalAddress senderHardwareAddress;
        PhysicalAddress targetHardwareAddress;
        if (hardwareType == HardwareType.Ethernet)
        {
            senderHardwareAddress = new PhysicalAddress(packetBytes.Skip(packetStartPosition + 8).Take(6).ToArray());
            targetHardwareAddress = new PhysicalAddress(packetBytes.Skip(packetStartPosition + 18).Take(6).ToArray());
        } 
        else
        {
            throw new InvalidDataException($"Unsupported hardware type: '{hardwareType}'");
        }

        IPAddress senderProtocolAddress;
        IPAddress targetProtocolAddress;
        if (EtherType == EtherType.IPv4 ||
            EtherType == EtherType.IPv6)
        {
            senderProtocolAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 14).Take(4).ToArray());
            targetProtocolAddress = new IPAddress(packetBytes.Skip(packetStartPosition + 24).Take(4).ToArray());
        }
        else
        {
            throw new InvalidDataException($"Unsupported EtherType: '{EtherType}'");
        }

        return new ArpPacket(hardwareType, EtherType, HardwareAddressLength, ProtocolAddressLength, OperationCode, senderHardwareAddress, senderProtocolAddress, targetHardwareAddress, targetProtocolAddress);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ArpPacket" /> class.
    /// </summary>
    /// <param name="hardwareType">The source and target hardware type.</param>
    /// <param name="etherType">The higher network layer protocol.</param>
    /// <param name="hardwareAddressLength">The total length of the hardware addresses.</param>
    /// <param name="protocolAddressLength">The total length of the protocol addresses.</param>
    /// <param name="operationCode">The ARP operation type.</param>
    /// <param name="senderHardwareAddress">The source hardware address.</param>
    /// <param name="senderProtocolAddress">The source network protocol address.</param>
    /// <param name="targetHardwareAddress">The target hardware address.</param>
    /// <param name="targetProtocolAddress">The target network protocol address.</param>
    public ArpPacket(
        HardwareType hardwareType,
        EtherType etherType,
        int hardwareAddressLength,
        int protocolAddressLength,
        OperationCode operationCode,
        PhysicalAddress senderHardwareAddress,
        IPAddress senderProtocolAddress,
        PhysicalAddress targetHardwareAddress,
        IPAddress targetProtocolAddress)
    {
        HardwareType = hardwareType;
        EtherType = etherType;
        HardwareAddressLength = hardwareAddressLength;
        ProtocolAddressLength = protocolAddressLength;
        OperationCode = operationCode;
        SenderHardwareAddress = senderHardwareAddress ?? throw new ArgumentNullException(nameof(senderHardwareAddress));
        SenderProtocolAddress = senderProtocolAddress ?? throw new ArgumentNullException(nameof(senderProtocolAddress));
        TargetHardwareAddress = targetHardwareAddress ?? throw new ArgumentNullException(nameof(targetHardwareAddress));
        TargetProtocolAddress = targetProtocolAddress ?? throw new ArgumentNullException(nameof(targetProtocolAddress));
    }

    /// <summary>
    /// Gets the hardware type of the source and target hardware addresses.
    /// </summary>
    public HardwareType HardwareType { get; }

    /// <summary>
    /// Gets the ethertype of the network layer above ARP.
    /// </summary>
    public EtherType EtherType { get; }

    /// <summary>
    /// Gets the hardware address length in bytes.
    /// </summary>
    public int HardwareAddressLength { get; }

    /// <summary>
    /// Gets the protocol address length in bytes.
    /// </summary>
    public int ProtocolAddressLength { get; }

    /// <summary>
    /// Gets the ARP operation type code.
    /// </summary>
    public OperationCode OperationCode { get; }

    /// <summary>
    /// Gets the sender hardware address value.
    /// </summary>
    public PhysicalAddress SenderHardwareAddress { get; }

    /// <summary>
    /// Gets the sender protocol address value.
    /// </summary>
    public IPAddress SenderProtocolAddress { get; }

    /// <summary>
    /// Gets the target hardware address value.
    /// </summary>
    public PhysicalAddress TargetHardwareAddress { get; }

    /// <summary>
    /// Gets the target protocol address value.
    /// </summary>
    public IPAddress TargetProtocolAddress { get; }

    /// <inheritdoc />
    public override IPAddress SourceAddress => SenderProtocolAddress;

    /// <inheritdoc />
    public override IPAddress DestinationAddress => TargetProtocolAddress;

    /// <inheritdoc />
    public override NetworkPacketProtocol Protocol => NetworkPacketProtocol.ARP;
}
