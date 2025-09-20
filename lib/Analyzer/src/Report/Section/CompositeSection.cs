// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// A composite section containing subsections.
/// </summary>
public abstract class CompositeSection : Section
{
    /// <summary>
    /// Gets subsections.
    /// </summary>
    public abstract IEnumerable<ISection> Subsections { get; }

    /// <summary>
    /// Gets composite section header title.
    /// </summary>
    protected virtual string? CompositeHeaderTitle => null;

    /// <summary>
    /// Gets composite section header description.
    /// </summary>
    protected virtual string? CompositeHeaderDescription => null;

    /// <inheritdoc />
    protected override void RenderSection(IRenderer renderer)
    {
        if (!string.IsNullOrWhiteSpace(CompositeHeaderTitle) ||
            !string.IsNullOrWhiteSpace(CompositeHeaderDescription))
        {
            renderer.AddHeader(CompositeHeaderTitle, CompositeHeaderDescription);
        }

        foreach (var subsection in Subsections)
        {
            subsection.Render(renderer);
        }
    }
}
