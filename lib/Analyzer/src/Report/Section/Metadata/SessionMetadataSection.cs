// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Metadata;

/// <summary>
/// The packet capture session metadata information.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SessionMetadataSection" /> class.
/// </remarks>
/// <param name="metadata">The packet capture session metadata.</param>
/// <param name="reportVersion">The version of the report.</param>
public class SessionMetadataSection(SessionMetadata metadata, string? reportVersion = default) : ISection
{
    private readonly SessionMetadata _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
    private readonly string? _reportVersion = reportVersion;

    /// <inheritdoc />
    public void Render(IRenderer renderer)
    {
        renderer.StartSection();
        renderer.AddSectionTitle("Metadata");
        renderer.AddHeader(null, "Metadata on the packet capture, packet analysis and report generation process.");

        var rows = new List<string[]>();

        foreach (var data in _metadata.AdditionalMetadata)
        {
            rows.Add([data.Key, data.Value]);
        }

        rows.Add(["Capture start time", _metadata.StartCaptureTime?.ToStringFormat() ?? "N/A"]);
        rows.Add(["Capture end time", _metadata.EndCaptureTime?.ToStringFormat() ?? "N/A"]);
        rows.Add(["Capture duration", _metadata.CaptureDuration?.ToString() ?? "N/A"]);
        rows.Add(["Report version", _reportVersion ?? "N/A"]);

        renderer.AddTable(["Name", "Value"], rows);
        renderer.EndSection();
    }
}
