// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report;

/// <summary>
/// Base class to reports.
/// </summary>
public class BaseReport : IReport
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BaseReport" /> class.
    /// </summary>
    /// <param name="sections">The sections of the report for displaying information.</param>
    public BaseReport(IEnumerable<ISection> sections)
    {
        _ = sections ?? throw new ArgumentNullException(nameof(sections));
        Sections = new List<ISection>(sections);
    }

    /// <summary>
    /// Gets or sets the collection of sections used for the report.
    /// </summary>
    public virtual IEnumerable<ISection> Sections { get; protected set; }

    /// <summary>
    /// Renders the report, typically rendering all sections of the Report.
    /// </summary>
    /// <typeparam name="TRenderer">Renderer format type.</typeparam>
    /// <param name="renderer">Renders the sections.</param>
    /// <returns><paramref name="renderer" /> containing the rendered sections.</returns>
    public TRenderer Render<TRenderer>(TRenderer renderer)
        where TRenderer : IRenderer
    {
        foreach (var section in Sections)
        {
            section.Render(renderer);
        }

        return renderer;
    }
}
