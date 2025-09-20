// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Test.Reader.Utils;

internal class BlockOptionByteConversionUtil
{
    internal static byte[] ConvertOptionFieldToByte(ushort optionType, byte[] value)
    {
        var alignmentBoundary = 4;
        var ret = new List<byte>();

        var remainderLength = (alignmentBoundary - (value.Length % alignmentBoundary)) % alignmentBoundary;

        ret.AddRange(BitConverter.GetBytes(optionType));
        ret.AddRange(BitConverter.GetBytes((ushort)value.Length));

        if (value.Length >= 0)
        {
            ret.AddRange(value);
            for (var i = 0; i < remainderLength; i++)
            {
                ret.Add(0);
            }
        }

        return [.. ret];
    }

    internal static byte[] CreateSectionHeaderBlockOptionBytes(string comment, string hardware, string operatingSystem, string userApplication)
    {
        var resultBytes = new List<byte>();
        var commentBytes = Encoding.UTF8.GetBytes(comment);
        var hardwareBytes = Encoding.UTF8.GetBytes(hardware);
        var operatingSystemBytes = Encoding.UTF8.GetBytes(operatingSystem);
        var userApplicationBytes = Encoding.UTF8.GetBytes(userApplication);

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)SectionHeaderOptionCode.CommentCode, commentBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)SectionHeaderOptionCode.HardwareCode, hardwareBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)SectionHeaderOptionCode.OperatingSystemCode, operatingSystemBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)SectionHeaderOptionCode.UserApplicationCode, userApplicationBytes));

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)SectionHeaderOptionCode.EndOfOptionsCode, []));

        return [.. resultBytes];
    }

    internal static byte[] CreateInterfaceDescriptionBlockOptionBytes(
        string comment,
        string name,
        string description,
        IPAddress ipv4Address,
        IPAddress ipv6Address,
        PhysicalAddress macAddress,
        byte[] euiAddress,
        long speed,
        byte timestampResolution,
        int timezone,
        byte[] filter,
        string operatingSystem,
        byte frameCheckSequence,
        long timeOffsetSeconds)
    {
        byte[] ipv4OptionBytesMask = [255, 255, 255, 0];
        byte[] ipv6OptionBytesLength = [64];

        var resultBytes = new List<byte>();
        var commentBytes = Encoding.UTF8.GetBytes(comment);
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var descriptionBytes = Encoding.UTF8.GetBytes(description);
        var ipv4AddressBytes = ipv4Address != IPAddress.None ? [.. ipv4Address.GetAddressBytes(), .. ipv4OptionBytesMask] : ipv4Address.GetAddressBytes(); // add mask
        var ipv6AddressBytes = ipv6Address != IPAddress.None ? [.. ipv6Address.GetAddressBytes(), .. ipv6OptionBytesLength] : ipv6Address.GetAddressBytes(); // add prefix length
        var macAddressBytes = macAddress.GetAddressBytes();
        var speedBytes = BitConverter.GetBytes(speed);
        var timezoneBytes = BitConverter.GetBytes(timezone);
        var operatingSystemBytes = Encoding.UTF8.GetBytes(operatingSystem);
        var timeOffsetSecondsBytes = BitConverter.GetBytes(timeOffsetSeconds);

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.CommentCode, commentBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.NameCode, nameBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.DescriptionCode, descriptionBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.IPv4AddressCode, ipv4AddressBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.IPv6AddressCode, ipv6AddressBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.MacAddressCode, macAddressBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.EuiAddressCode, euiAddress));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.SpeedCode, speedBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.TimestampResolutionCode, [timestampResolution]));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.TimeZoneCode, timezoneBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.FilterCode, filter));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.OperatingSystemCode, operatingSystemBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.FrameCheckSequenceCode, [frameCheckSequence]));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.TimeOffsetSecondsCode, timeOffsetSecondsBytes));

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceDescriptionOptionCode.EndOfOptionsCode, []));

        return [.. resultBytes];
    }

    internal static byte[] CreateInterfaceStatisticsBlockOptionBytes(
        string comment,
        uint startTimestampHigh,
        uint startTimestampLow,
        uint endimestampHigh,
        uint endimestampLow,
        long interfaceReceived,
        long interfaceDrop,
        long filterAccept,
        long systemDrop,
        long deliveredToUser)
    {
        var resultBytes = new List<byte>();
        var commentBytes = Encoding.UTF8.GetBytes(comment);
        var startTimestampBytes = BitConverter.GetBytes(startTimestampHigh).Concat(BitConverter.GetBytes(startTimestampLow)).ToArray();
        var endimestampBytes = BitConverter.GetBytes(endimestampHigh).Concat(BitConverter.GetBytes(endimestampLow)).ToArray();
        var interfaceReceivedBytes = BitConverter.GetBytes(interfaceReceived);
        var interfaceDropBytes = BitConverter.GetBytes(interfaceDrop);
        var filterAcceptBytes = BitConverter.GetBytes(filterAccept);
        var systemDropBytes = BitConverter.GetBytes(systemDrop);
        var deliveredToUserBytes = BitConverter.GetBytes(deliveredToUser);

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.CommentCode, commentBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.StartTimeCode, startTimestampBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.EndTimeCode, endimestampBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.InterfaceReceivedCode, interfaceReceivedBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.InterfaceDropCode, interfaceDropBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.FilterAcceptCode, filterAcceptBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.SystemDropCode, systemDropBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.DeliveredToUserCode, deliveredToUserBytes));

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)InterfaceStatisticsOptionCode.EndOfOptionsCode, []));

        return [.. resultBytes];
    }

    internal static byte[] CreateEnhancedPacketBlockOptionBytes(
        string comment,
        uint packetFlag,
        long dropCount,
        byte[] hashBlockBytes)
    {
        var resultBytes = new List<byte>();
        var commentBytes = Encoding.UTF8.GetBytes(comment);
        var packetFlagBytes = BitConverter.GetBytes(packetFlag);
        var dropCountBytes = BitConverter.GetBytes(dropCount);

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)EnhancedPacketOptionCode.CommentCode, commentBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)EnhancedPacketOptionCode.PacketFlagCode, packetFlagBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)EnhancedPacketOptionCode.DropCountCode, dropCountBytes));
        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)EnhancedPacketOptionCode.HashCode, hashBlockBytes));

        resultBytes.AddRange(ConvertOptionFieldToByte((ushort)EnhancedPacketOptionCode.EndOfOptionsCode, []));

        return [.. resultBytes];
    }
}