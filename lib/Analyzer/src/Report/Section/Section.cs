// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// A section containing subsections.
/// </summary>
public abstract class Section : ISection
{
    /// <summary>
    /// Gets section title. Optional parameter - the title will not be rendered if the value is null or white space.
    /// </summary>
    protected virtual string? SectionTitle => null;

    /// <inheritdoc />
    public void Render(IRenderer renderer)
    {
        if (!string.IsNullOrWhiteSpace(SectionTitle))
        {
            renderer.AddSectionTitle(SectionTitle);
        }

        RenderSection(renderer);
    }

    /// <summary>
    /// Render the section to an <see cref="IRenderer" />.
    /// </summary>
    /// <param name="renderer">Section renderer.</param>
    protected abstract void RenderSection(IRenderer renderer);
}
