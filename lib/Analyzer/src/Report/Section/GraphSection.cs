// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Graph;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// Graph section.
/// </summary>
public abstract class GraphSection : Section
{
    private long[]? _xAxisData;
    private long[]? _yAxisData;

    /// <summary>
    /// Gets a value indicating whether the section should be rendered.
    /// </summary>
    [MemberNotNullWhen(true, nameof(XAxisData), nameof(YAxisData))]
    public bool ShouldBeRendered => XAxisData?.Length > 0 && YAxisData?.Length > 0;

    /// <summary>
    /// Gets message for when a graph cannot be created because no relevant data exists.
    /// </summary>
    protected abstract string NoDataMessage { get; }

    /// <summary>
    /// Gets graph header title.
    /// </summary>
    protected abstract string GraphHeaderTitle { get; }

    /// <summary>
    /// Gets graph header title.
    /// </summary>
    protected abstract string GraphHeaderDescription { get; }

    /// <summary>
    /// Gets graph x-axis label.
    /// </summary>
    protected abstract string GraphXAxisLabel { get; }

    /// <summary>
    /// Gets graph y-axis label.
    /// </summary>
    protected abstract string GraphYAxisLabel { get; }

    /// <summary>
    /// Gets graph x-axis value formatter.
    /// </summary>
    protected abstract Func<long, string> GraphXAxisValueFormatter { get; }

    /// <summary>
    /// Gets graph y-axis value formatter.
    /// </summary>
    protected abstract Func<long, string> GraphYAxisValueFormatter { get; }

    private long[]? XAxisData => _xAxisData ??= GetXAxisData();

    private long[]? YAxisData => _yAxisData ??= GetYAxisData();

    /// <summary>
    /// Gets graph x-axis data.
    /// </summary>
    /// <returns>Array of graph x-axis data.</returns>
    protected abstract long[]? GetXAxisData();

    /// <summary>
    /// Gets graph y-axis data.
    /// </summary>
    /// <returns>Array of graph y-axis data.</returns>
    protected abstract long[]? GetYAxisData();

    /// <inheritdoc />
    protected override void RenderSection(IRenderer renderer)
    {
        if (!ShouldBeRendered)
        {
            renderer.AddMessage(NoDataMessage);
            return;
        }

        renderer.AddHeader(GraphHeaderTitle, GraphHeaderDescription);
        renderer.AddGraph(
            new GraphData(
                xAxisLabel: GraphXAxisLabel,
                yAxisLabel: GraphYAxisLabel,
                xAxisData: XAxisData,
                yAxisData: YAxisData),
            xValueFormatter: GraphXAxisValueFormatter,
            yValueFormatter: GraphYAxisValueFormatter);
    }
}
