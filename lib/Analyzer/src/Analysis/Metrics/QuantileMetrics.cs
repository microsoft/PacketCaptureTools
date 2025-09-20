// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Metrics;

/// <summary>
/// Quantile metrics class.
/// </summary>
/// <typeparam name="T">Type of metric.</typeparam>
public abstract class QuantileMetrics<T> : StatisticMetrics<T> 
    where T: notnull
{
    private const int MinimumPercentile = 0;
    private const int MaximumPercentile = 100;

    private readonly SortedDictionary<T, ulong> _sparseMetricCounter;

    /// <summary>
    /// Initializes a new instance of the <see cref="QuantileMetrics{T}" /> class.
    /// </summary>
    /// <param name="customComparer">Custom comparator for metrics.</param>
    public QuantileMetrics(Comparer<T>? customComparer = default)
        : base(customComparer)
    {
        _sparseMetricCounter = [];
    }

    /// <summary>
    /// Gets mean of values for this metric.
    /// </summary>
    /// <returns>Value at given percentile.</returns>
    public T Median => GetValueForPercentile(50);

    /// <inheritdoc />
    public override void Insert(T item)
    {
        var key = HashFunction(item);

        if (!_sparseMetricCounter.ContainsKey(key))
        {
            _sparseMetricCounter.Add(key, 0);
        }

        _sparseMetricCounter[key] += 1;

        base.Insert(item);
    }

    /// <summary>
    /// Get value for given percentile.
    /// </summary>
    /// <param name="percentile">Percentile value.</param>
    /// <returns>Value at given percentile.</returns>
    public T GetValueForPercentile(int percentile)
    {
        if (percentile < MinimumPercentile ||
            percentile > MaximumPercentile)
        {
            throw new ArgumentOutOfRangeException(
                nameof(percentile),
                $"Percentile is not between {MinimumPercentile} and {MaximumPercentile}");
        }

        if (Count <= 0)
        {
            throw new Exception("No values found in metrics.");
        }

        // Fraction can be calculated by dividing the percentile by 100.
        // Once you have a fraction you can calculate the location for that fraction by multiplying it with the total items.
        var countPosition = Math.Ceiling(((double)percentile / MaximumPercentile) * Count);
        foreach (var kvPair in _sparseMetricCounter)
        {
            countPosition -= kvPair.Value;

            if (countPosition <= 0)
            {
                return kvPair.Key;
            }
        }

        throw new KeyNotFoundException($"No value found for percentile: '{percentile}'");
    }

    /// <summary>
    /// Gets hash function for calculating metric key.
    /// </summary>
    /// <param name="item">Item to calculate hash of.</param>
    /// <returns>Hashed item.</returns>
    protected abstract T HashFunction(T item);
}
