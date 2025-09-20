// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Report.Table.Ascii;

/// <summary>
/// Ascii Table Formatter.
/// </summary>
internal class AsciiTable
{
    private const int ColumnPadding = 3;
    private const int EmptyColumnPadding = 4;

    private readonly int _tableWidth;
    private readonly int[] _columnWidths;
    private readonly string _rowline;
    private readonly IReadOnlyList<string> _headers;
    private readonly IReadOnlyList<IReadOnlyList<string>> _rows;
    private readonly Func<string, int, string> _alignText;

    /// <summary>
    /// Initializes a new instance of the <see cref="AsciiTable" /> class.
    /// </summary>
    private AsciiTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows, bool alignCenter)
    {
        _headers = headers;
        _rows = rows;
        _columnWidths = GetColumnWidths();
        _tableWidth = _columnWidths.Sum() + 1;
        _rowline = CreateRowline();

        if (alignCenter)
        {
            _alignText = AlignCenter;
        }
        else
        {
            _alignText = AlignLeft;
        }
    }

    /// <summary>
    /// Creates instance of class and Ascii Formatted Table.
    /// </summary>
    /// <param name="headers">List of table headers.</param>
    /// <param name="rows">List of table rows.</param>
    /// <param name="alignCenter">Align text to center.</param>
    /// <returns>Ascii string containing formatted table.</returns>
    /// <exception cref="ArgumentNullException">Throws if <paramref name="headers" /> or <paramref name="rows" /> is null.</exception>
    /// .
    /// <exception cref="ArgumentException">Throws if <paramref name="headers" /> length and length of row of <paramref name="rows" /> is unequal.</exception>
    internal static string CreateTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows, bool alignCenter = false)
    {
        _ = headers ?? throw new ArgumentNullException(nameof(headers));
        _ = rows ?? throw new ArgumentNullException(nameof(rows));

        if (!headers.Any())
        {
            throw new ArgumentException($"'{nameof(headers)}' cannot be empty, one or more headers must be provided.", nameof(headers));
        }

        foreach (var row in rows)
        {
            if (row == null)
            {
                throw new ArgumentNullException(nameof(rows), $"'{nameof(row)}' cannot be null, one or more row entries must be provided.");
            }

            if (headers.Count != row.Count)
            {
                throw new ArgumentException($"The row '{string.Join(", ", row)}' has {row.Count} entries which does not match the entries in the header {headers.Count}.");
            }
        }

        return new AsciiTable(headers, rows, alignCenter).CreateTableInternal();
    }

    /// <summary>
    /// Creates a Ascii Formatted Table.
    /// </summary>
    /// <returns>Ascii string containing formatted table.</returns>
    private string CreateTableInternal()
    {
        var table = new StringBuilder();

        table.AppendLine(_rowline);
        table.AppendLine(CreateHeaderRow());
        table.AppendLine(_rowline);
        table.Append(AddTableRows());
        table.Append(_rowline);

        return table.ToString();
    }

    /// <summary>
    /// Creates rows of Ascii Formatted Table.
    /// </summary>
    /// <returns>String containing table rows.</returns>
    private string AddTableRows()
    {
        var table = new StringBuilder();
        int columnIndex;

        foreach (var row in _rows)
        {
            table.Append('|');
            columnIndex = 0;

            foreach (var entry in row)
            {
                table.Append(_alignText(entry, _columnWidths[columnIndex++]));
            }

            table.AppendLine();
        }

        return table.ToString();
    }

    /// <summary>
    /// Creates header row of Ascii Table.
    /// </summary>
    /// <returns>String containing header row.</returns>
    private string CreateHeaderRow()
    {
        var headerRow = new StringBuilder("|");

        var columnIndex = 0;
        foreach (var header in _headers)
        {
            headerRow.Append(_alignText(header, _columnWidths[columnIndex++]));
        }

        return headerRow.ToString();
    }

    /// <summary>
    /// Alignes text to the left.
    /// </summary>
    /// <returns>Left aligned text in table entry.</returns>
    private string AlignLeft(string entry, int columnWidth)
    {
        entry = entry ?? "_";
        var alignedEntry = new string(' ', columnWidth).ToArray();

        entry.CopyTo(0, alignedEntry, 1, entry.Length);
        alignedEntry[columnWidth - 1] = '|';

        return new string(alignedEntry);
    }

    /// <summary>
    /// Alignes text to the center.
    /// </summary>
    /// <returns>Center aligned text in table entry.</returns>
    private string AlignCenter(string entry, int columnWidth)
    {
        entry = entry ?? "_";
        var alignedEntry = new string(' ', columnWidth).ToArray();

        entry.CopyTo(0, alignedEntry, (columnWidth / 2) - (entry.Length / 2), entry.Length);
        alignedEntry[columnWidth - 1] = '|';

        return new string(alignedEntry);
    }

    /// <summary>
    /// Get width of each table column.
    /// </summary>
    /// <returns>Array containing width of each table column.</returns>
    private int[] GetColumnWidths()
    {
        var columnIndex = 0;
        var columnWidths = new int[_headers.Count];
        foreach (var header in _headers)
        {
            columnWidths[columnIndex++] = header?.Length + ColumnPadding ?? EmptyColumnPadding;
        }

        foreach (var row in _rows)
        {
            columnIndex = 0;
            foreach (var entry in row)
            {
                columnWidths[columnIndex] = Math.Max(columnWidths[columnIndex], entry?.Length + ColumnPadding ?? EmptyColumnPadding);
                columnIndex++;
            }
        }

        return columnWidths;
    }

    /// <summary>
    /// Creates table line seperator.
    /// </summary>
    /// <returns>String representation of table line seperator.</returns>
    private string CreateRowline()
    {
        var rowlineArray = new string('-', _tableWidth).ToCharArray();

        var cumulativeColumnWidth = 0;
        foreach (var width in _columnWidths)
        {
            cumulativeColumnWidth += width;
            rowlineArray[cumulativeColumnWidth] = '+';
        }

        rowlineArray[0] = '+';

        return new string(rowlineArray);
    }
}
