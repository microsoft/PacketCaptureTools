// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;

/// <summary>
/// Interface Description block options.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="InterfaceDescriptionOption" /> class.
/// </remarks>
/// <param name="binaryReader">Binary reader with interface description header block option bytes.</param>
/// <param name="optionsBlockSize">The size of the options block in bytes.</param>
internal class InterfaceDescriptionOption(BinaryReader binaryReader, int optionsBlockSize) : Option(binaryReader, optionsBlockSize)
{
    /// <summary>
    /// Gets a UTF-8 string containing a comment that is associated to the current block.
    /// </summary>
    public string? Comment
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.CommentCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the name of the device used to capture data.
    /// </summary>
    public string? Name
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.NameCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the description of the device used to capture data.
    /// </summary>
    public string? Description
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.DescriptionCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets the device interface IPv4 network address.
    /// </summary>
    public IPAddress? IPv4Address
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.IPv4AddressCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return new IPAddress([.. bytes.Take(4)]).MapToIPv4();
        }
    }

    /// <summary>
    /// Gets the device interface IPv4 subnet mask.
    /// </summary>
    public IPAddress? IPv4AddressSubnetMask
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.IPv4AddressCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return new IPAddress([.. bytes.Skip(4).Take(4)]).MapToIPv4();
        }
    }

    /// <summary>
    /// Gets the device interface IPv6 network address.
    /// </summary>
    public IPAddress? IPv6Address
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.IPv6AddressCode);

            if (bytes == null ||
                bytes.Length != 17)
            {
                return null;
            }

            return new IPAddress([.. bytes.Take(16)]).MapToIPv6();
        }
    }

    /// <summary>
    /// Gets the device interface IPv6 prefix length.
    /// </summary>
    public byte? IPv6AddressPrefixLength
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.IPv6AddressCode);

            if (bytes == null ||
                bytes.Length != 17)
            {
                return null;
            }

            return bytes[16];
        }
    }

    /// <summary>
    /// Gets the interface Hardware MAC address.
    /// </summary>
    public PhysicalAddress? MacAddress
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.MacAddressCode);

            if (bytes == null ||
                bytes.Length != 6)
            {
                return null;
            }

            return new PhysicalAddress(bytes);
        }
    }

    /// <summary>
    /// Gets the interface Hardware EUI address (64 bits).
    /// </summary>
    public byte[]? EuiAddress
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.EuiAddressCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return bytes;
        }
    }

    /// <summary>
    /// Gets the interface speed (in bps).
    /// </summary>
    public long? Speed
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.SpeedCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the resolution of timestamps.
    /// </summary>
    public byte? TimestampResolution
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.TimestampResolutionCode);

            if (bytes == null ||
                bytes.Length != 1)
            {
                return null;
            }

            return bytes[0];
        }
    }

    /// <summary>
    /// Gets the time zone for GMT support.
    /// </summary>
    public int? TimeZone
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.TimeZoneCode);

            if (bytes == null ||
                bytes.Length != 4)
            {
                return null;
            }

            return BitConverter.ToInt32(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the filter used to capture traffic.
    /// </summary>
    public byte[]? Filter
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.FilterCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return bytes;
        }
    }

    /// <summary>
    /// Gets a UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
    /// </summary>
    public string? OperatingSystem
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.OperatingSystemCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets an integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
    /// </summary>
    public byte? FrameCheckSequence
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.FrameCheckSequenceCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return bytes[0];
        }
    }

    /// <summary>
    /// Gets a 64 bits integer value that specifies an offset (in seconds) that must be added to the timestamp of each packet to obtain
    /// the absolute timestamp of a packet.
    /// </summary>
    public long? TimeOffsetSeconds
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceDescriptionOptionCode.TimeOffsetSecondsCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }
}
