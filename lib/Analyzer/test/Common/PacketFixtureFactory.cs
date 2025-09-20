// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Packet.Network;
using Microsoft.PacketCapture.Analyzer.Packet.Network.ARP;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V4;
using Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6;
using Microsoft.PacketCapture.Analyzer.Packet.Physical;
using Microsoft.PacketCapture.Analyzer.Packet.Transport;
using Microsoft.PacketCapture.Analyzer.Packet.Transport.TCP;
using System;
using System.Net;
using System.Net.NetworkInformation;

namespace Microsoft.PacketCapture.Analyzer.Test.Common;

internal class PacketFixtureFactory
{
    internal CapturedPacket CreateCapturedPacketFixture(
        PhysicalFrame? physicalFrame = null,
        NetworkPacket? networkPacket = null,
        TransportSegment? transportSegment = null,
        int originalPacketLength = 0,
        DateTime? capturedDateTime = null,
        byte[]? payload = null,
        int frameNumber = 1)
    {
        return new CapturedPacket(
            payload: payload ?? Array.Empty<byte>(),
            originalPacketLength: originalPacketLength,
            physicalFrame: physicalFrame,
            networkPacket: networkPacket,
            transportSegment: transportSegment,
            capturedDateTime: capturedDateTime,
            frameNumber: frameNumber);
    }

    internal EthernetFrame CreateEthernetFrameFixture(
        NetworkPacket networkPacket,
        EtherType etherType = EtherType.IPv4)
    {
        return new EthernetFrame(
            sourceMacAddress: PhysicalAddress.None,
            destinationMacAddress: PhysicalAddress.None,
            etherType: etherType,
            networkPacket: networkPacket);
    }

    internal IPv4Packet CreateIPv4PacketFixture(
        TransportSegment? transportSegment,
        IPAddress? sourceIpAddress = null,
        IPAddress? destinationIpAddress = null,
        int headerLengthInWords = 0,
        int totalLength = 0)
    {
        return new IPv4Packet(
            version: 0,
            headerLengthInWords: headerLengthInWords,
            DscpValue.DF,
            totalLength: totalLength,
            identification: 0,
            flags: IPv4Flag.None,
            fragmentOffset: 0,
            timeToLive: 0,
            ipProtocol: IpProtocol.TCP,
            sourceAddress: sourceIpAddress ?? IPAddress.None,
            destinationAddress: destinationIpAddress ?? IPAddress.None,
            transportSegment: transportSegment);
    }

    internal IPv6Packet CreateIPv6PacketFixture(
        TransportSegment transportSegment,
        IPAddress? sourceIpAddress = null,
        IPAddress? destinationIpAddress = null)
    {
        return new IPv6Packet(
            version: 0,
            DscpValue.DF,
            ecnCode: 0,
            flowLabel: 0,
            payloadLength: 0,
            ipProtocol: IpProtocol.TCP,
            hopLimit: 0,
            sourceAddress: sourceIpAddress ?? IPAddress.None,
            destinationAddress: destinationIpAddress ?? IPAddress.None,
            transportSegment: transportSegment);
    }

    internal ArpPacket CreateArpPacketFixture(
        IPAddress? senderProtocolAddress = null,
        IPAddress? targetProtocolAddress = null)
    {
        return new ArpPacket(
            hardwareType: HardwareType.Ethernet,
            etherType: EtherType.IPv4,
            hardwareAddressLength: 0,
            protocolAddressLength: 4,
            operationCode: OperationCode.Request,
            senderHardwareAddress: PhysicalAddress.None,
            senderProtocolAddress: senderProtocolAddress ?? IPAddress.None,
            targetHardwareAddress: PhysicalAddress.None,
            targetProtocolAddress: targetProtocolAddress ?? IPAddress.None);
    }

    internal TcpSegment CreateTcpSegmentFixture(
        int sourcePort = 0,
        int destinationPort = 0,
        uint sequenceNumber = 0,
        uint acknowledgementNumber = 0,
        TcpFlags? tcpFlags = default,
        uint dataOffset = 0,
        uint payloadSize = 0,
        byte[]? payload = default)
    {
        byte[] payLoadBytes;

        if (payloadSize == 0 &&
            payload?.Length > 0)
        {
            payLoadBytes = payload;
        }
        else
        {
            payLoadBytes = new byte[payloadSize];
        }

        return new TcpSegment(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            sequenceNumber: sequenceNumber,
            ackNumber: acknowledgementNumber,
            dataOffsetInWords: dataOffset % 4 == 0 ? dataOffset / 4 : (dataOffset / 4) + 1,
            flags: tcpFlags ?? new TcpFlags(),
            window: 0,
            payload: payLoadBytes,
            nonTruncatedSize: (int)(dataOffset + payloadSize));
    }
}