// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Graph;
using Microsoft.PacketCapture.Analyzer.Report.Graph.Ascii;
using Microsoft.PacketCapture.Analyzer.Report.Table.Ascii;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Report.Render;

/// <summary>
/// Renders a visualisation of the Analyses in .txt format.
/// </summary>
public class TextRenderer : IRenderer
{
    private readonly StringBuilder _stringBuilder;

    /// <summary>
    /// Initializes a new instance of the <see cref="TextRenderer" /> class.
    /// </summary>
    public TextRenderer()
    {
        _stringBuilder = new StringBuilder();
    }

    /// <inheritdoc />
    public void AddGraph(GraphData graphData, Func<long, string> xValueFormatter, Func<long, string> yValueFormatter)
    {
        if (graphData.XAxisData.Length != graphData.YAxisData.Length)
        {
            throw new ArgumentException($"Invalid graph parameters: '{nameof(graphData.XAxisData)}' length and '{nameof(graphData.YAxisData)}' length should be equal, actual values {graphData.XAxisData.Length}' and $'{graphData.YAxisData.Length}'.");
        }

        _stringBuilder.AppendLine(AsciiGraph.Plot(graphData, xValueFormatter, yValueFormatter));
        _stringBuilder.AppendLine();
    }

    /// <inheritdoc />
    public void AddKeyValue(string key, string value)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = value ?? throw new ArgumentNullException(nameof(value));

        _stringBuilder.AppendLine($"{key}: {value}");
    }

    /// <inheritdoc />
    public void AddTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows)
    {
        _ = headers ?? throw new ArgumentNullException(nameof(headers));
        _ = rows ?? throw new ArgumentNullException(nameof(rows));

        _stringBuilder.AppendLine(AsciiTable.CreateTable(headers, rows));
        _stringBuilder.AppendLine();
    }

    /// <inheritdoc />
    public void AddHeader(string? header, string? headerText)
    {
        if (!string.IsNullOrEmpty(header))
        {
            _stringBuilder.AppendLine($"[{header}]");
        }

        if (!string.IsNullOrEmpty(headerText))
        {
            _stringBuilder.AppendLine(headerText);
        }

        if (!string.IsNullOrEmpty(header) || !string.IsNullOrEmpty(headerText))
        {
            _stringBuilder.AppendLine();
        }
    }

    /// <inheritdoc />
    public void AddSectionTitle(string title)
    {
        _ = title ?? throw new ArgumentNullException(nameof(title));

        _stringBuilder.AppendLine(title);
        _stringBuilder.AppendLine(new string('-', title.Length));
        _stringBuilder.AppendLine();
    }

    /// <inheritdoc />
    public void AddMessage(string message)
    {
        _stringBuilder.AppendLine(message ?? throw new ArgumentNullException(nameof(message)));
        _stringBuilder.AppendLine();
    }

    /// <summary>
    /// Returns render in String format.
    /// </summary>
    /// <returns>Render in String format.</returns>
    public override string ToString()
    {
        return _stringBuilder.ToString();
    }
}
