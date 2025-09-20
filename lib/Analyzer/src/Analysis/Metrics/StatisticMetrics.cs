// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Metrics;

/// <summary>
/// Statistics metrics class.
/// </summary>
/// <typeparam name="T">Type of metric.</typeparam>
/// <remarks>
/// Initializes a new instance of the <see cref="StatisticMetrics{T}" /> class.
/// </remarks>
/// <param name="customComparer">Custom comparator for metrics.</param>
public abstract class StatisticMetrics<T>(Comparer<T>? customComparer = default)
{
    private readonly Comparer<T> _customComparer = customComparer ?? Comparer<T>.Default;

    /// <summary>
    /// Gets the count of metrics.
    /// </summary>
    /// <returns>Total count of metrics.</returns>
    public ulong Count { get; private set; }

    /// <summary>
    /// Gets maximum value for this metric.
    /// </summary>
    /// <returns>Maximum value.</returns>
    public T? Maximum { get; private set; }

    /// <summary>
    /// Gets minimum value for this metric.
    /// </summary>
    /// <returns>Minimum value.</returns>
    public T? Minimum { get; private set; }

    /// <summary>
    /// Gets total of values for this metric.
    /// </summary>
    /// <returns>Total of values.</returns>
    public decimal Total { get; private set; }

    /// <summary>
    /// Gets average of values for this metric.
    /// </summary>
    /// <returns>Average value.</returns>
    public T? Average => AverageValueFromTotalAndCount(Total, Count);

    /// <summary>
    /// Gets a value indicating whether there are items in this metric.
    /// </summary>
    /// <returns>Boolean indicating if there are items.</returns>
    public bool IsEmpty => Count == 0;

    /// <summary>
    /// Insert value.
    /// </summary>
    /// <param name="item">item to insert.</param>
    public virtual void Insert(T item)
    {
        MaintainMinAndMax(item);
        CalculateTotal(item);
        Count += 1;
    }

    /// <summary>
    /// Gets function for calculating metric to use for total.
    /// </summary>
    /// <param name="item">Item to calculate total of.</param>
    /// <returns>value to use for calculating total.</returns>
    protected abstract decimal ExtractValueToCalculateTotal(T item);

    /// <summary>
    /// Gets function for calculating average from total and count.
    /// </summary>
    /// <param name="total">Total of metrics.</param>
    /// <param name="count">Count of metrics.</param>
    /// <returns>Average value.</returns>
    protected abstract T AverageValueFromTotalAndCount(decimal total, ulong count);

    private void MaintainMinAndMax(T item)
    {
        if (IsEmpty)
        {
            Minimum = item;
            Maximum = item;
        }

        if (_customComparer.Compare(Maximum, item) <= 0)
        {
            Maximum = item;
        }

        if (_customComparer.Compare(Minimum, item) > 0)
        {
            Minimum = item;
        }
    }

    private void CalculateTotal(T item)
    {
        Total += ExtractValueToCalculateTotal(item);
    }
}
