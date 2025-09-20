// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Render;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.PacketCapture.Analyzer.Report.Section;

/// <summary>
/// Table section.
/// </summary>
public abstract class TableSection : Section
{
    private List<string[]>? _tableData;

    /// <summary>
    /// Gets a value indicating whether the section should be rendered.
    /// </summary>
    [MemberNotNullWhen(true, nameof(TableData))]
    public bool ShouldBeRendered => TableData?.Count > 0;

    /// <summary>
    /// Gets table header title.
    /// </summary>
    protected abstract string TableHeaderTitle { get; }

    /// <summary>
    /// Gets table header description.
    /// </summary>
    protected abstract string? TableHeaderDescription { get; }

    /// <summary>
    /// Gets message for when a table cannot be created because no relevant data exists.
    /// </summary>
    protected abstract string NoDataMessage { get; }

    /// <summary>
    /// Gets table column headers.
    /// </summary>
    protected abstract string[] TableHeaders { get; }

    private List<string[]>? TableData => _tableData ??= GetTableData();

    /// <summary>
    /// Gets table data.
    /// </summary>
    /// <returns>List containing table data rows.</returns>
    protected abstract List<string[]>? GetTableData();

    /// <inheritdoc />
    protected override void RenderSection(IRenderer renderer)
    {
        if (!ShouldBeRendered)
        {
            renderer.AddMessage(NoDataMessage);
            return;
        }

        renderer.AddHeader(TableHeaderTitle, TableHeaderDescription);
        renderer.AddTable(TableHeaders, TableData);
    }
}
