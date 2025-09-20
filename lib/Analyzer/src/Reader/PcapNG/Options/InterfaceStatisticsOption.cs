// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options.Codes;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG.Options;

/// <summary>
/// Interface Statistics Option.
/// </summary>
internal sealed class InterfaceStatisticsOption : Option
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InterfaceStatisticsOption" /> class.
    /// </summary>
    /// <param name="binaryReader">Binary reader with interface statistics header block option bytes.</param>
    /// <param name="optionsBlockSize">The size of the options block in bytes.</param>
    public InterfaceStatisticsOption(BinaryReader binaryReader, int optionsBlockSize)
        : base(binaryReader, optionsBlockSize)
    {
    }

    /// <summary>
    /// Gets a UTF-8 string containing a comment that is associated to the current block.
    /// </summary>
    public string? Comment
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.CommentCode);

            if (bytes == null ||
                bytes.Length < 1)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    /// <summary>
    /// Gets the time in which the capture started; time will be stored in two blocks of four bytes each.
    /// </summary>
    public DateTime? StartTime
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.StartTimeCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            var unixCapturedTimeHigh = BitConverter.ToUInt32(bytes.Take(4).ToArray(), 0);
            var unixCapturedTimeLow = BitConverter.ToUInt32(bytes.Skip(4).Take(4).ToArray(), 0);

            return DateTimeOffset.FromUnixTimeMilliseconds((unixCapturedTimeHigh << 32) + unixCapturedTimeLow).UtcDateTime;
        }
    }

    /// <summary>
    /// Gets the time in which the capture ended time will be stored in two blocks of four bytes each.
    /// </summary>
    public DateTime? EndTime
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.EndTimeCode);

            if (bytes == null ||
                bytes.Length != 8)
            {
                return null;
            }

            var unixCapturedTimeHigh = BitConverter.ToUInt32(bytes.Take(4).ToArray(), 0);
            var unixCapturedTimeLow = BitConverter.ToUInt32(bytes.Skip(4).Take(4).ToArray(), 0);

            return DateTimeOffset.FromUnixTimeMilliseconds((unixCapturedTimeHigh << 32) + unixCapturedTimeLow).UtcDateTime;
        }
    }

    /// <summary>
    /// Gets the number of packets received from the physical interface starting from the beginning of the capture.
    /// </summary>
    public long? InterfaceReceived
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.InterfaceReceivedCode);

            if (bytes == null ||
                bytes.Length < 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the number of packets dropped by the interface due to lack of resources starting from the beginning of the capture.
    /// </summary>
    public long? InterfaceDrop
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.InterfaceDropCode);

            if (bytes == null ||
                bytes.Length < 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the number of packets accepted by filter starting from the beginning of the capture.
    /// </summary>
    public long? FilterAccept
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.FilterAcceptCode);

            if (bytes == null ||
                bytes.Length < 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the number of packets dropped by the operating system starting from the beginning of the capture.
    /// </summary>
    public long? SystemDrop
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.SystemDropCode);

            if (bytes == null ||
                bytes.Length < 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }

    /// <summary>
    /// Gets the number of packets delivered to the user starting from the beginning of the capture.
    /// </summary>
    public long? DeliveredToUser
    {
        get
        {
            var bytes = GetOption((ushort)InterfaceStatisticsOptionCode.DeliveredToUserCode);

            if (bytes == null ||
                bytes.Length < 8)
            {
                return null;
            }

            return BitConverter.ToInt64(bytes, 0);
        }
    }
}
