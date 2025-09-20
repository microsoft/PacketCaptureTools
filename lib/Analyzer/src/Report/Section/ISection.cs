// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// A section defines the relationship between analysis and the representation generated via an <see cref="IRenderer" />.
/// </summary>
public interface ISection
{
    /// <summary>
    /// Render the section to an <see cref="IRenderer" />.
    /// </summary>
    /// <param name="renderer">Render used to convert analysis to visual.</param>
    void Render(IRenderer renderer);
}
