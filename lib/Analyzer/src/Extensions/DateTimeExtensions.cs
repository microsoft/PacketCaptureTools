// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Globalization;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Extensions for DateTime types.
/// </summary>
internal static class DateTimeExtensions
{
    /// <summary>
    /// Truncates a <see cref="DateTime" /> object to seconds.
    /// </summary>
    /// <param name="dateTime">Original DateTime.</param>
    /// <returns>A new <see cref="DateTime" /> object truncated to seconds.</returns>
    public static DateTime TruncateToSeconds(this DateTime dateTime)
    {
        return dateTime.AddTicks(-(dateTime.Ticks % TimeSpan.TicksPerSecond));
    }

    /// <summary>
    /// Converts a <see cref="DateTime" /> to a string with a format similar to ISO 8601 but slightly adapted for human readability.
    /// </summary>
    /// <param name="dateTime">Original DateTime.</param>
    /// <returns>Formatted string.</returns>
    public static string ToStringFormat(this DateTime dateTime)
    {
        return dateTime.ToString("yyyy-MM-dd HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
    }
}
