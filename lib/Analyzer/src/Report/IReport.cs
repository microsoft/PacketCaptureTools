// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report;

/// <summary>
/// Defines the logical report that is generated from the packet capture analysis.
/// </summary>
public interface IReport
{
    /// <summary>
    /// Gets the collection of sections used for the report.
    /// </summary>
    IEnumerable<ISection> Sections { get; }

    /// <summary>
    /// Renders the sections for the Report class.
    /// </summary>
    /// <param name="renderer">Renderer used to render section.</param>
    /// <typeparam name="TRenderer">Type of renderer, must implement <see cref="IRenderer" />.</typeparam>
    /// <returns>The rendered section of the Report.</returns>
    TRenderer Render<TRenderer>(TRenderer renderer)
        where TRenderer : IRenderer;
}
