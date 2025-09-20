// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Metrics;

/// <summary>
/// Timestamp metrics class.
/// </summary>
public class TimestampMetrics : QuantileMetrics<TimeSpan>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TimestampMetrics"/> class.
    /// </summary>
    public TimestampMetrics()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TimestampMetrics"/> class containing initial metrics.
    /// </summary>
    /// <param name="initalMetrics">Initial metrics.</param>
    public TimestampMetrics(IEnumerable<TimeSpan> initalMetrics)
    {
        if (initalMetrics is null)
        {
            return;
        }

        foreach (var initalMetric in initalMetrics)
        {
            Insert(initalMetric);
        }
    }

    /// <summary>
    /// Returns human readable string for timestamp at given percentile value.
    /// </summary>
    /// <param name="percentile">Percentile of value.</param>
    /// <returns>Human readable timestamp or <see langword="null"/> when no available timestamp is available.</returns>
    public string? GetTimestampForPercentile(int percentile)
    {
        try
        {
            return GetValueForPercentile(percentile).ToReadableFormat();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <inheritdoc />
    protected override decimal ExtractValueToCalculateTotal(TimeSpan item) => (decimal)item.TotalMilliseconds;

    /// <inheritdoc />
    protected override TimeSpan AverageValueFromTotalAndCount(decimal total, ulong count) =>
        TimeSpan.FromMilliseconds((double)(total / count));

    /// <inheritdoc />
    protected override TimeSpan HashFunction(TimeSpan t)
    {
        if (t.Minutes > 0)
        {
            // Trimmed to seconds
            return TimeSpan.FromMilliseconds(t.TotalMilliseconds - (t.TotalMilliseconds % 1000));
        }

        if (t.Seconds > 10)
        {
            // Trimmed to 100 milliseconds
            return TimeSpan.FromMilliseconds(t.TotalMilliseconds - (t.TotalMilliseconds % 100));
        }

        if (t.Seconds > 0)
        {
            // Trimmed to 10 milliseconds
            return TimeSpan.FromMilliseconds(t.TotalMilliseconds - (t.TotalMilliseconds % 10));
        }

        return t;
    }
}
