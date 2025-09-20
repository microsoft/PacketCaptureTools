// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Help;

/// <summary>
/// Help section.
/// </summary>
public class HelpSection : Section
{
    private readonly string _helpText;

    /// <summary>
    /// Initializes a new instance of the <see cref="HelpSection" /> class.
    /// </summary>
    /// <param name="helpText">Help text.</param>
    public HelpSection(string helpText) => _helpText = helpText;

    /// <inheritdoc />
    protected override string? SectionTitle => ShouldBeRendered ? "Help" : null;

    private bool ShouldBeRendered => !string.IsNullOrEmpty(_helpText);

    /// <inheritdoc />
    protected override void RenderSection(IRenderer renderer)
    {
        if (!ShouldBeRendered)
        {
            return;
        }

        renderer.AddMessage(_helpText);
    }
}
