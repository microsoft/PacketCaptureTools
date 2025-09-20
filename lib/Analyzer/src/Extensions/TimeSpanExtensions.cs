// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Extensions for <see cref="TimeSpan" />.
/// </summary>
internal static class TimeSpanExtensions
{
    /// <summary>
    /// Convert a <see cref="TimeSpan" />? to a human readable format.
    /// </summary>
    /// <param name="source">The source timespan.</param>
    /// <returns>Timespan in human readable format, null if <see cref="source" /> is null.</returns>
    public static string? ToReadableFormat(this TimeSpan? source)
    {
        return source?.ToReadableFormat();
    }

    /// <summary>
    /// Convert a <see cref="TimeSpan" /> to a human readable format.
    /// </summary>
    /// <param name="source">The source timespan.</param>
    /// <returns>Timespan in human readable format.</returns>
    public static string ToReadableFormat(this TimeSpan source)
    {
        if (source.TotalDays >= 1)
        {
            return source.Hours > 0 && source.Days < 100
                ? $"{source.Days}d {source.Hours}h"
                : $"{source.Days} d";
        }

        if (source.TotalHours >= 1)
        {
            return source.Minutes > 0
                ? $"{source.Hours}h {source.Minutes}m"
                : $"{source.Hours} h";
        }

        if (source.TotalMinutes >= 1)
        {
            return source.Seconds > 0
                ? $"{source.Minutes}m {source.Seconds}s"
                : $"{source.Minutes} m";
        }

        if (source.TotalSeconds >= 1)
        {
            return source.Milliseconds >= 10
                ? $"{source.Seconds}{(source.TotalSeconds >= 10 ? $"{source:\\.f}" : $"{source:\\.ff}")} s"
                : $"{source.Seconds} s";
        }

        if (source.TotalMilliseconds > 0)
        {
            return $"{source.Milliseconds} ms";
        }

        return "0 ms";
    }
}
