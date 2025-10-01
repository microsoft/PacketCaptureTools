// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Converter;

/// <summary>
/// Represents the result of a packet conversion operation.
/// </summary>
/// <param name="ElapsedTime">The total time taken to complete the conversion operation.</param>
/// <param name="ConvertedPackets">The number of packets that were successfully converted during the operation.</param>
/// <param name="Errors">A collection of exceptions representing errors that occurred during the conversion. The collection is empty if no
/// errors were encountered.</param>
public record ConversionResult(TimeSpan ElapsedTime, long ConvertedPackets, IEnumerable<Exception> Errors);
