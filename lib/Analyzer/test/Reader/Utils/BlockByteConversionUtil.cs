// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader.Common;
using Microsoft.PacketCapture.Analyzer.Reader.PcapNG;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;

internal class BlockByteConversionUtil
{
    internal static byte[] CreateSectionHeaderBlockBytes(MagicNumber magicNumber, ushort majorVersion, ushort minorVersion, long sectionLength, byte[] sectionHeaderOptionBytes)
    {
        var resultBytes = new List<byte>();
        var magicNumberBytes = BitConverter.GetBytes((uint)magicNumber);
        var majorVersionBytes = BitConverter.GetBytes(majorVersion);
        var minorVersionBytes = BitConverter.GetBytes(minorVersion);
        var sectionLengthBytes = BitConverter.GetBytes(sectionLength);

        resultBytes.AddRange(magicNumberBytes);
        resultBytes.AddRange(majorVersionBytes);
        resultBytes.AddRange(minorVersionBytes);
        resultBytes.AddRange(sectionLengthBytes);
        resultBytes.AddRange(sectionHeaderOptionBytes);

        return resultBytes.ToArray();
    }

    internal static byte[] CreateInterfaceDescriptionBlockBytes(LinkType linktype, int snapLen, byte[] interfaceDescriptionBlockOptionsBytes)
    {
        var resultBytes = new List<byte>();
        var linkTypeBytes = BitConverter.GetBytes((ushort)linktype);
        byte[] reservedBytes = { 0, 0 };
        var snapLenBytes = BitConverter.GetBytes(snapLen);

        resultBytes.AddRange(linkTypeBytes);
        resultBytes.AddRange(reservedBytes);
        resultBytes.AddRange(snapLenBytes);
        resultBytes.AddRange(interfaceDescriptionBlockOptionsBytes);

        return resultBytes.ToArray();
    }

    internal static byte[] CreateInterfaceStatisticsBlockBytes(int interfaceId, uint timestampHigh, uint timestampLow, byte[] interfaceStatisticsBlockOptionsBytes)
    {
        var resultBytes = new List<byte>();
        var interfaceIdBytes = BitConverter.GetBytes(interfaceId);
        var timestampHighBytes = BitConverter.GetBytes(timestampHigh);
        var timestampLowBytes = BitConverter.GetBytes(timestampLow);

        resultBytes.AddRange(interfaceIdBytes);
        resultBytes.AddRange(timestampHighBytes);
        resultBytes.AddRange(timestampLowBytes);
        resultBytes.AddRange(interfaceStatisticsBlockOptionsBytes);

        return resultBytes.ToArray();
    }

    internal static byte[] CreateEnhancedPacketBlockBytes(int interfaceId, uint timestampHigh, uint timestampLow, int capturedLength, int originalCapturedLength, byte[] data, byte[] enhancedPacketBlockOptionsBytes)
    {
        var resultBytes = new List<byte>();
        var interfaceIdBytes = BitConverter.GetBytes(interfaceId);
        var timestampHighBytes = BitConverter.GetBytes(timestampHigh);
        var timestampLowBytes = BitConverter.GetBytes(timestampLow);
        var capturedLengthBytes = BitConverter.GetBytes(capturedLength);
        var originalCapturedLengthBytes = BitConverter.GetBytes(originalCapturedLength);

        resultBytes.AddRange(interfaceIdBytes);
        resultBytes.AddRange(timestampHighBytes);
        resultBytes.AddRange(timestampLowBytes);
        resultBytes.AddRange(capturedLengthBytes);
        resultBytes.AddRange(originalCapturedLengthBytes);
        resultBytes.AddRange(data);

        /// pad with 0s to 32-bits
        var remainderLength = PacketUtils.PcapAlignmentBoundary - (data.Length % PacketUtils.PcapAlignmentBoundary);
        resultBytes.AddRange(Enumerable.Repeat((byte)0, remainderLength));

        resultBytes.AddRange(enhancedPacketBlockOptionsBytes);

        return resultBytes.ToArray();
    }

    internal static byte[] CreateSimplePacketBlockBytes(int packetLength, byte[] packetData)
    {
        var resultBytes = new List<byte>();
        var packetLengthBytes = BitConverter.GetBytes(packetLength);

        resultBytes.AddRange(packetLengthBytes);
        resultBytes.AddRange(packetData);

        /// pad with 0s to 32-bits
        var remainderLength = PacketUtils.PcapAlignmentBoundary - (packetData.Length % PacketUtils.PcapAlignmentBoundary);
        resultBytes.AddRange(Enumerable.Repeat((byte)0, remainderLength));

        return resultBytes.ToArray();
    }
}