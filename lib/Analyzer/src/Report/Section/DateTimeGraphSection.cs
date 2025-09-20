// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// Tcp Packet Reset Graph Section which graphs the Tcp resets over time.
/// </summary>
public abstract class DateTimeGraphSection : GraphSection
{
    /// <summary>
    /// Gets graph x-axis DateTime format.
    /// </summary>
    protected abstract string GraphXAxisDateTimeFormat { get; }

    /// <inheritdoc />
    protected override Func<long, string> GraphXAxisValueFormatter => x => new DateTime(x).ToString(GraphXAxisDateTimeFormat);

    /// <inheritdoc />
    protected override Func<long, string> GraphYAxisValueFormatter => x => x.ToString();
}
