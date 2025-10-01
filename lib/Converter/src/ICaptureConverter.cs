// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Converter;

/// <summary>
/// Packet Capture Converter.
/// </summary>
public interface ICaptureConverter : IDisposable
{
    /// <summary>
    /// Converts packet capture from source to destination formats.
    /// </summary>
    /// <returns>Returns the result of the conversion operation.</returns>
    ConversionResult Convert();
}
