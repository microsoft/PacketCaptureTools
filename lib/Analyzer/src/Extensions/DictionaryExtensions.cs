// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Extensions for Dictionary types.
/// </summary>
internal static class DictionaryExtensions
{
    /// <summary>
    /// Insert <see cref="value" /> to <see cref="TimestampMetrics" /> at <see cref="key" />, or create a new <see cref="TimestampMetrics" /> with <see cref="value" /> element if <see cref="TimestampMetrics" /> does not exist.
    /// </summary>
    /// <typeparam name="TKey">Dictionary key type.</typeparam>
    /// <param name="source">Source dictionary.</param>
    /// <param name="key">Dictionary key.</param>
    /// <param name="value">TimestampMetrics TimeSpan value.</param>
    /// <returns>An updated dictionary.</returns>
    public static Dictionary<TKey, TimestampMetrics> InsertIntoMetrics<TKey>(this Dictionary<TKey, TimestampMetrics> source, TKey key, TimeSpan value)
        where TKey : notnull
    {
        if (!source.ContainsKey(key))
        {
            source[key] = new TimestampMetrics();
        }

        source[key].Insert(value);

        return source;
    }

    /// <summary>
    /// Add <see cref="value" /> to <see cref="List{TValue}" /> at <see cref="key" />. Create a new <see cref="List{TValue}" /> first it it doesn't exist.
    /// </summary>
    /// <typeparam name="TKey">Dictionary key type.</typeparam>
    /// <typeparam name="TValue">Dictionary list value type.</typeparam>
    /// <param name="source">Source dictionary.</param>
    /// <param name="key">Dictionary key.</param>
    /// <param name="value">Dictionary list value.</param>
    /// <returns>An updated dictionary.</returns>
    public static Dictionary<TKey, List<TValue>> AddToList<TKey, TValue>(this Dictionary<TKey, List<TValue>> source, TKey key, TValue value)
        where TKey : notnull
    {
        if (!source.ContainsKey(key))
        {
            source[key] = new List<TValue>();
        }

        source[key].Add(value);

        return source;
    }
}
