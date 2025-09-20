// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Enum generic extensions.
/// </summary>
/// <typeparam name="TEnum">Enum type.</typeparam>
internal class Enum<TEnum>
    where TEnum : struct, IConvertible
{
    /// <summary>
    /// Create a dictionary where keys are <see cref="TEnum" /> values and values are <see cref="defaultValue" />.
    /// </summary>
    /// <typeparam name="TValue">Dictionary value type.</typeparam>
    /// <param name="defaultValue">Default value for every dictionary entry.</param>
    /// <returns>Dictionary containing an entry for every value of <see cref="TEnum" />.</returns>
    public static Dictionary<TEnum, TValue?> AsDictionary<TValue>(TValue? defaultValue = default)
    {
        return Enum.GetValues(typeof(TEnum)).Cast<TEnum>().ToDictionary(x => x, _ => defaultValue);
    }
}
