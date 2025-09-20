// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Extensions for enum types.
/// </summary>
internal static class EnumExtensions
{
    /// <summary>
    /// Gets the enum value based on the <c>int</c> value the enum maps to.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an int.</param>
    /// <param name="exceptionMessage">An exception message when the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    /// <exception cref="Exception">If the enum lookup fails.</exception>
    public static TEnum GetEnumValue<TEnum>(int lookupValue, string exceptionMessage)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        throw new Exception(exceptionMessage);
    }

    /// <summary>
    /// Gets the enum value based on the <c>int</c> value the enum maps to, or return a default value.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an int.</param>
    /// <param name="defaultValue">Default value to return if the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    public static TEnum GetEnumValueOrDefault<TEnum>(int lookupValue, TEnum defaultValue)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        return defaultValue;
    }

    /// <summary>
    /// Gets the enum value based on the <c>uint</c> value the enum maps to.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an uint.</param>
    /// <param name="exceptionMessage">An exception message when the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    /// <exception cref="Exception">If the enum lookup fails.</exception>
    public static TEnum GetEnumValue<TEnum>(uint lookupValue, string exceptionMessage)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        throw new Exception(exceptionMessage);
    }

    /// <summary>
    /// Gets the enum value based on the <c>uint</c> value the enum maps to, or return a default value.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an uint.</param>
    /// <param name="defaultValue">Default value to return if the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    public static TEnum GetEnumValueOrDefault<TEnum>(uint lookupValue, TEnum defaultValue)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        return defaultValue;
    }

    /// <summary>
    /// Gets the enum value based on the <c>ushort</c> value the enum maps to.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an ushort.</param>
    /// <param name="exceptionMessage">An exception message when the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    /// <exception cref="Exception">If the enum lookup fails.</exception>
    public static TEnum GetEnumValue<TEnum>(ushort lookupValue, string exceptionMessage)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        throw new Exception(exceptionMessage);
    }

    /// <summary>
    /// Gets the enum value based on the <c>ushort</c> value the enum maps to, or return a default value.
    /// </summary>
    /// <typeparam name="TEnum">The enum type.</typeparam>
    /// <param name="lookupValue">The enums value as an ushort.</param>
    /// <param name="defaultValue">Default value to return if the lookup fails.</param>
    /// <returns><see cref="TEnum" /> value.</returns>
    public static TEnum GetEnumValueOrDefault<TEnum>(ushort lookupValue, TEnum defaultValue)
        where TEnum : Enum, IConvertible
    {
        if (Enum.IsDefined(typeof(TEnum), lookupValue))
        {
            return (TEnum)(IConvertible)lookupValue;
        }

        return defaultValue;
    }
}
