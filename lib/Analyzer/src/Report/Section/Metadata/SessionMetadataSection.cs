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
public class SessionMetadataSection : ISection
{
    private readonly SessionMetadata _metadata;
    private readonly string? _reportVersion;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionMetadataSection" /> class.
    /// </summary>
    /// <param name="metadata">The packet capture session metadata.</param>
    /// <param name="reportVersion">The version of the report.</param>
    public SessionMetadataSection(SessionMetadata metadata, string? reportVersion = default)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _reportVersion = reportVersion;
    }

    /// <inheritdoc />
    public void Render(IRenderer renderer)
    {
        renderer.AddSectionTitle("Metadata");
        renderer.AddHeader(null, "Metadata on the packet capture, packet analysis and report generation process.");

        var rows = new List<string[]>();

        foreach (var data in _metadata.AdditionalMetadata)
        {
            rows.Add(new[] { data.Key, data.Value });
        }

        rows.Add(new[] { "Capture start time", _metadata.StartCaptureTime?.ToStringFormat() ?? "N/A" });
        rows.Add(new[] { "Capture end time", _metadata.EndCaptureTime?.ToStringFormat() ?? "N/A" });
        rows.Add(new[] { "Capture duration", _metadata.CaptureDuration?.ToString() ?? "N/A" });
        rows.Add(new[] { "Report version", _reportVersion ?? "N/A" });

        renderer.AddTable(new List<string> { "Name", "Value" }, rows);
    }
}
