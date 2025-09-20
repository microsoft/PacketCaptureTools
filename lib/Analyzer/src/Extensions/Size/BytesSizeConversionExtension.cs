// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Extensions.Size;

/// <summary>
/// Bytes to human readable size convertor extension.
/// </summary>
internal static class BytesSizeConversionExtension
{
    /// <summary>
    /// Default precision format.
    /// </summary>
    public const string DefaultPrecisionFormat = "##";

    /// <summary>
    /// Round number format.
    /// </summary>
    public const string RoundNumberFormat = "";

    private const int OneKiloByte = 1024;

    private static readonly SizeEnumManager SizeEnumManager = new SizeEnumManager();

    /// <summary>
    /// Returns human readable size string for bytes.
    /// </summary>
    /// <param name="value">value in bytes.</param>
    /// <param name="precisionFormat">custom precision format.</param>
    /// <param name="sizeCap">custom size cap.</param>
    /// <returns>Human Readable size.</returns>
    public static string GetHumanReadableSize(
        this long value,
        string precisionFormat = DefaultPrecisionFormat,
        SizeEnum sizeCap = default)
        => InternalGetHumanReadableSize(value, precisionFormat, sizeCap);

    /// <summary>
    /// Returns human readable size string for bytes.
    /// </summary>
    /// <param name="value">value in bytes.</param>
    /// <param name="precisionFormat">custom precision format.</param>
    /// <param name="sizeCap">custom size cap.</param>
    /// <returns>Human Readable size.</returns>
    public static string GetHumanReadableSize(
        this ulong value,
        string precisionFormat = DefaultPrecisionFormat,
        SizeEnum sizeCap = default)
        => InternalGetHumanReadableSize(value, precisionFormat, sizeCap);

    /// <summary>
    /// Returns human readable size string for bytes.
    /// </summary>
    /// <param name="value">value in bytes.</param>
    /// <param name="precisionFormat">custom precision format.</param>
    /// <param name="sizeCap">custom size cap.</param>
    /// <returns>Human Readable size.</returns>
    public static string GetHumanReadableSize(
        this double value,
        string precisionFormat = DefaultPrecisionFormat,
        SizeEnum sizeCap = default)
        => InternalGetHumanReadableSize(value, precisionFormat, sizeCap);

    private static string InternalGetHumanReadableSize(
        double value,
        string precisionFormat = DefaultPrecisionFormat,
        SizeEnum sizeCap = default)
    {
        if (value == 0)
        {
            return $"0 {SizeEnumManager[0]}";
        }

        var closestExponent = Convert.ToInt32(Math.Floor(Math.Log(value, OneKiloByte)));

        // Sanitize exponent in case log was between 0 and -1
        var sanitizedExponent = Math.Max(closestExponent, 0);
        var chosenExponent = sizeCap == default ? sanitizedExponent : SizeEnumManager[sizeCap];

        value /= Math.Pow(OneKiloByte, chosenExponent);

        return string.Format($"{{0:0.{precisionFormat}}} {{1}}", value, SizeEnumManager[chosenExponent]);
    }
}