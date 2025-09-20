// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report.Graph;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Render;

/// <summary>
/// Defines a renderer used to render sections of an <see cref="IReport" />. The renderer should support creating the defined set of representations.
/// </summary>
public interface IRenderer
{
    /// <summary>
    /// Render a table with the given headers and rows.
    /// </summary>
    /// <param name="headers">List of table headers.</param>
    /// <param name="rows">List of table rows.</param>
    void AddTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows);

    /// <summary>
    /// Render a graph.
    /// </summary>
    /// <param name="graphData">Graph data including the X and Y axis data and labels.</param>
    /// <param name="xValueFormatter">Converts X value into x-axis label.</param>
    /// <param name="yValueFormatter">Converts Y value into y-axis label.</param>
    void AddGraph(GraphData graphData, Func<long, string> xValueFormatter, Func<long, string> yValueFormatter);

    /// <summary>
    /// Render a key and value pair.
    /// </summary>
    /// <param name="key">Key of the pair.</param>
    /// <param name="value">Value of the pair.</param>
    void AddKeyValue(string key, string value);

    /// <summary>
    /// Renders a header. Typically used to delimiter analyses inside a section.
    /// </summary>
    /// <param name="title">Header title text.</param>
    /// <param name="description">Header description text.</param>
    void AddHeader(string? title, string? description);

    /// <summary>
    /// Renders a section header. Typically used to delimiter sections within a report.
    /// </summary>
    /// <param name="title">Section header title text.</param>
    void AddSectionTitle(string title);

    /// <summary>
    /// Renders a message.
    /// </summary>
    /// <param name="message">A message to render.</param>
    void AddMessage(string message);
}
