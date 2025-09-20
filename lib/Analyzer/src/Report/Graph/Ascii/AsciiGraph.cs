// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Text;

namespace Microsoft.PacketCapture.Analyzer.Report.Graph.Ascii;

/// <summary>
/// Ascii Graph Library.
/// </summary>
internal class AsciiGraph
{
    private const int MinPlotHeight = 10;
    private const int MinPlotWidth = 40;
    private const int MinXAxisInterval = 10;
    private const int MaxPlotHeight = 20;
    private const int MaxPlotWidth = 80;
    private const int MaxXAxisInterval = 60;
    private const int XBucketDefault = 5;
    private const int YBucketDefault = 1;

    private readonly GraphData _graphData;
    private readonly long _smallestXValue;
    private readonly long _xBucket;
    private readonly long _yBucket;
    private readonly Func<long, string> _xLabelFormatter;
    private readonly Func<long, string> _yLabelFormatter;
    private readonly int _plotWidth;
    private readonly int _plotHeight;
    private readonly long _xAxisInterval;

    private StringBuilder? _plot;

    /// <summary>
    /// Initializes a new instance of the <see cref="AsciiGraph" /> class.
    /// </summary>
    /// <param name="graphData">The graph X and Y axis labels and data.</param>
    /// <param name="xLabelFormatter">Converts X value into x-axis label.</param>
    /// <param name="yLabelFormatter">Converts Y value into y-axis label.</param>
    /// <param name="plotWidth">Scales down the x-axis.</param>
    /// <param name="plotHeight">Scales down the y-axis.</param>
    /// <param name="xAxisInterval">Interval where y-axis labels are plotted.</param>
    internal AsciiGraph(GraphData graphData, Func<long, string> xLabelFormatter, Func<long, string> yLabelFormatter, int plotWidth, int plotHeight, long xAxisInterval)
    {
        _graphData = graphData ?? throw new ArgumentNullException(nameof(graphData));

        _xLabelFormatter = xLabelFormatter;
        _yLabelFormatter = yLabelFormatter;
        _smallestXValue = graphData.XAxisData.Min();
        (_plotWidth, _plotHeight, xAxisInterval) = SetGraphSize(plotWidth, plotHeight, xAxisInterval);
        (_xBucket, _yBucket, _xAxisInterval) = FitGraphToWindow(graphData.XAxisData, graphData.YAxisData, xAxisInterval, XBucketDefault, YBucketDefault);
        _graphData = NormaliseAxis(graphData);
    }

    /// <summary>
    /// Plots a graph in Ascii format returned as a string.
    /// </summary>
    /// <param name="graphData">The graph X and Y axis labels and data.</param>
    /// <param name="xLabelFormatter">Converts X value into x-axis label.</param>
    /// <param name="yLabelFormatter">Converts Y value into y-axis label.</param>
    /// <param name="plotWidth">Sets width of the plot.</param>
    /// <param name="plotHeight">Sets height of the plot.</param>
    /// <param name="xAxisInterval">Interval where y-axis labels are plotted.</param>
    /// <returns>String graph representation of the graph.</returns>
    internal static string Plot(GraphData graphData, Func<long, string> xLabelFormatter, Func<long, string> yLabelFormatter, int plotWidth = MaxPlotWidth, int plotHeight = MaxPlotHeight, int xAxisInterval = MaxXAxisInterval)
    {
        if (graphData.XAxisData.Length < 1)
        {
            return $"Insufficient packets supplied. At least two packets are needed to build a graph, actual number of packets: {graphData.XAxisData.Length}.";
        }

        if (graphData.XAxisData.Length != graphData.YAxisData.Length)
        {
            return $"Invalid graph parameters: Inconsistent amount of X and Y data. Values for X axis: {graphData.XAxisData.Length}', values for Y axis: $'{graphData.YAxisData.Length}'.";
        }

        xLabelFormatter ??= (x => x.ToString());
        yLabelFormatter ??= (y => y.ToString());

        return new AsciiGraph(graphData, xLabelFormatter, yLabelFormatter, plotWidth, plotHeight, xAxisInterval).PlotInternal();
    }

    /// <summary>
    /// Plots a graph in Ascii format returned as a string.
    /// </summary>
    /// <returns>String graph representation of the graph.</returns>
    private string PlotInternal()
    {
        var graphArray = BuildGraph();

        var lengthOfMaximumYValueLabel = (_graphData.YAxisData.Max() * _yBucket).ToString().Length;
        var lengthOfMinimumYValueLabel = (_graphData.YAxisData.Min() * _yBucket).ToString().Length;
        var xLabelLength = _xLabelFormatter((_graphData.XAxisData[^1] * _xBucket) + _smallestXValue).Length;

        // paddingLeftOfYAxis = Padding to the left of and including y-axis line.
        // Title char + 2 Spaces + Max Label Length + Axis line char.
        var paddingLeftOfYAxis = Math.Max(lengthOfMaximumYValueLabel, lengthOfMinimumYValueLabel) + 4;
        var yAxis = CreateYAxis(paddingLeftOfYAxis);
        var plot = BuildPlotString(graphArray, yAxis, xLabelLength / 2);
        var xAxis = CreateXAxis(paddingLeftOfYAxis, xLabelLength / 2);

        return plot + xAxis;
    }

    /// <summary>
    /// Plots the Ascii Graph within a 2D array.
    /// </summary>
    /// <returns>2D array representation of the 2D Array.</returns>
    private string[,] BuildGraph()
    {
        long currentYValue, nextYValue, horizontalLineStart, horizontalLineEnd;
        var graphYLength = Math.Max(_graphData.YAxisData.Max(), MinPlotHeight);
        var graphArray = InitialiseArray(new string[graphYLength + 1, _graphData.XAxisData.Max() + 2]);

        for (var i = 0; i < _graphData.XAxisData.Length - 1; i++)
        {
            currentYValue = _graphData.YAxisData[i] == -1 ? 0 : _graphData.YAxisData[i];
            nextYValue = _graphData.YAxisData[i + 1] == -1 ? 0 : _graphData.YAxisData[i + 1];

            // Use a flat "─" char if (both points are equal real y-values) or (y_1 = 0 and y_2 <= 0)
            var bothPointsAreSameY = _graphData.YAxisData[i] == _graphData.YAxisData[i + 1];
            var bothPointsAreRealValues = _graphData.YAxisData[i] != -1;
            var currPointHasZeroY = _graphData.YAxisData[i] == 0;
            var nextPointIsMinusOneOrZero = !(_graphData.YAxisData[i] < _graphData.YAxisData[i + 1]);

            if ((bothPointsAreSameY && bothPointsAreRealValues) ||
                (currPointHasZeroY && nextPointIsMinusOneOrZero))
            {
                graphArray[graphYLength - currentYValue, i] = "─";
            }
            else if (_graphData.YAxisData[i] != -1 ||
                     _graphData.YAxisData[i + 1] != -1)
            {
                graphArray[graphYLength - nextYValue, i] = currentYValue > nextYValue ? "╰" : "╭";
                graphArray[graphYLength - currentYValue, i] = currentYValue == nextYValue ? " " : currentYValue > nextYValue ? "╮" : "╯";

                horizontalLineStart = Math.Min(currentYValue, nextYValue);
                horizontalLineEnd = Math.Max(currentYValue, nextYValue);

                for (var j = horizontalLineStart + 1; j < horizontalLineEnd; j++)
                {
                    graphArray[graphYLength - j, i] = "│";
                }
            }
        }

        return graphArray;
    }

    /// <summary>
    /// Adjusts scale of graph.
    /// </summary>
    /// <param name="plotWidth">New plotWidth of graph.</param>
    /// <param name="plotHeight">New plotHeight of graph.</param>
    /// <param name="xAxisInterval">Interval where y-axis labels are plotted.</param>
    /// <returns>3-tuple containing the plot plotWidth, plotHeight and x-axis interval.</returns>
    private static (int, int, long) SetGraphSize(int plotWidth, int plotHeight, long xAxisInterval)
    {
        plotWidth = plotWidth >= MinPlotWidth && plotWidth <= MaxPlotWidth ? plotWidth : MaxPlotWidth;
        plotHeight = plotHeight >= MinPlotHeight && plotHeight <= MaxPlotHeight ? plotHeight : MaxPlotHeight;
        xAxisInterval = xAxisInterval >= MinXAxisInterval ? xAxisInterval : MaxXAxisInterval;

        return (plotWidth, plotHeight, xAxisInterval);
    }

    private (long, long, long) FitGraphToWindow(long[] xAxisData, long[] yAxisData, long xAxisInterval, long xBucket, long yBucket)
    {
        long xAxisMax = xAxisData.Max();

        if ((xAxisMax - _smallestXValue) / xBucket > _plotWidth)
        {
            xBucket = (long)Math.Ceiling((double)(xAxisMax - _smallestXValue) / _plotWidth);
        }

        var xSize = (long)Math.Ceiling((double)xAxisMax / xBucket) + 2 - (_smallestXValue / xBucket);
        xSize = Math.Max(xSize, MinPlotWidth);

        var findUpdatedYAxisMax = new long[xSize];
        long translatedXValue;
        for (var i = 0; i < yAxisData.Length; i++)
        {
            translatedXValue = (int)Math.Floor(((double)xAxisData[i] / xBucket) - (_smallestXValue / xBucket));
            findUpdatedYAxisMax[translatedXValue] += yAxisData[i];
        }

        long yAxisMax = findUpdatedYAxisMax.Max();

        if (yAxisMax / yBucket > _plotHeight)
        {
            yBucket = (long)Math.Ceiling((double)yAxisMax / _plotHeight);
        }

        if (xAxisInterval <= xBucket)
        {
            xAxisInterval = (_plotWidth * xBucket) / 5;
        }

        return (xBucket, yBucket, xAxisInterval);
    }

    /// <summary>
    /// Creates the labels for the y-axis.
    /// </summary>
    /// <param name="yAxisPadding">Padding to guarentee even label spacing.</param>
    /// <returns>String array containing y-axis labels and line.</returns>
    private string[] CreateYAxis(int yAxisPadding)
    {
        _ = _yLabelFormatter(_graphData.YAxisData[1]) ?? throw new ArgumentNullException($"Entry {1} of {nameof(_graphData.YAxisData)} using {nameof(_yLabelFormatter)}'");

        var yAxisMax = Math.Max(_graphData.YAxisData.Max(), MinPlotHeight);
        var yAxis = Enumerable.Repeat(" ", (int)(yAxisMax + 1)).ToArray();
        var titleStartIndex = (yAxis.Length / 2) - (_graphData.YAxisLabel.Length / 2);
        var titleFitsYAxis = _graphData.YAxisLabel.Length < yAxis.Length;

        if (titleFitsYAxis)
        {
            for (var i = 0; i < _graphData.YAxisLabel.Length; i++)
            {
                yAxis[titleStartIndex + i] = _graphData.YAxisLabel[i].ToString();
            }
        }

        for (var i = 0; i < yAxis.Length; i++)
        {
            yAxis[i] += (_yLabelFormatter((yAxisMax * _yBucket) - (i * _yBucket)) + "┤").PadLeft(yAxisPadding - 1, ' ');
        }

        return yAxis;
    }

    /// <summary>
    /// Builds the plotted section of the graph to string..
    /// </summary>
    /// <param name="graphArray">Array containing plot layout.</param>
    /// <returns>Plot formatted as a string.</returns>
    private string BuildPlotString(string[,] graphArray, string[] yAxis, int xLabelLength)
    {
        _plot = new StringBuilder();
        for (var i = 0; i < graphArray.GetLength(0); i++)
        {
            _plot.Append(yAxis[i]);
            for (var j = 0; j < graphArray.GetLength(1) - 1; j++)
            {
                _plot.Append(graphArray[i, j]);
            }

            _plot.AppendLine(string.Empty.PadLeft(xLabelLength, ' '));
        }

        return _plot.ToString();
    }

    /// <summary>
    /// Create the x-axis of the graph.
    /// </summary>
    /// <param name="paddingLeftOfYAxis">Padding to guarentee even label spacing.</param>
    /// <returns>X-axis formatted as a string.</returns>
    private string CreateXAxis(int paddingLeftOfYAxis, int xLabelLength)
    {
        var xaxis = new StringBuilder();

        _ = _xLabelFormatter(_graphData.XAxisData[1]) ?? throw new ArgumentNullException($"Entry {1} of {nameof(_graphData.XAxisData)} using {nameof(_xLabelFormatter)}'");

        var xAxisLine = Enumerable.Repeat(' ', paddingLeftOfYAxis).Concat(Enumerable.Repeat('-', _graphData.XAxisData.Length + xLabelLength)).ToArray();
        var xAxisValues = Enumerable.Repeat(' ', xAxisLine.Length).ToArray();
        if (_xBucket < _xAxisInterval)
        {
            for (var i = 0; i < xAxisLine.Length - paddingLeftOfYAxis; i++)
            {
                if (i % (_xAxisInterval / _xBucket) == 0)
                {
                    xAxisLine[i + paddingLeftOfYAxis] = '|';
                    var temp = _xLabelFormatter((_graphData.XAxisData[i] * _xBucket) + _smallestXValue);
                    temp.CopyTo(0, xAxisValues, (i - (temp.Length / 2)) + paddingLeftOfYAxis, temp.Length);
                }
            }
        }

        xAxisLine[paddingLeftOfYAxis] = '-';
        var xAxisLabelValues = Enumerable.Repeat(' ', xAxisLine.Length).ToArray();
        if ((xAxisLabelValues.Length / 2) + (_graphData.XAxisLabel.Length / 2) > _graphData.XAxisLabel.Length)
        {
            _graphData.XAxisLabel.CopyTo(0, xAxisLabelValues, (xAxisLabelValues.Length / 2) - (_graphData.XAxisLabel.Length / 2), _graphData.XAxisLabel.Length);
        }

        xaxis.AppendLine(new string(xAxisLine));
        xaxis.AppendLine(new string(xAxisValues));
        xaxis.Append(new string(xAxisLabelValues));

        return xaxis.ToString();
    }

    /// <summary>
    /// Initialises graph array with spaces.
    /// </summary>
    /// <param name="graphArray">Graph array we wish to fill.</param>
    /// <returns><paramref name="graphArray" /> filled with spaces.</returns>
    private static string[,] InitialiseArray(string[,] graphArray)
    {
        for (var i = 0; i < graphArray.GetLength(0); i++)
        {
            for (var j = 0; j < graphArray.GetLength(1); j++)
            {
                graphArray[i, j] = " ";
            }
        }

        return graphArray;
    }

    /// <summary>
    /// Normalises and Scales Graph axes.
    /// </summary>
    /// <returns>Normalised and scaled Graph axes.</returns>
    private GraphData NormaliseAxis(GraphData graphData)
    {
        var untranslatedMaxXIndex = (long)Math.Ceiling((double)graphData.XAxisData.Max() / _xBucket) + 2;
        var untranslatedMinXIndex = (long)Math.Ceiling((double)_smallestXValue / _xBucket);
        var xSize = Math.Max(untranslatedMaxXIndex - untranslatedMinXIndex, MinPlotWidth);

        var formattedX = new long[xSize];
        var formattedY = new long[xSize];
        for (var x = 0; x < formattedX.Length; x++)
        {
            formattedX[x] = x;
            formattedY[x] = -1;
        }

        long translatedXValue;
        for (var x = 0; x < graphData.XAxisData.Length; x++)
        {
            translatedXValue = (int)Math.Floor(((double)graphData.XAxisData[x] / _xBucket) - ((double)_smallestXValue / _xBucket));
            if (formattedY[translatedXValue] < 0)
            {
                formattedY[translatedXValue] = 0;
            }

            formattedY[translatedXValue] += graphData.YAxisData[x] / _yBucket;
        }

        return new GraphData(graphData.XAxisLabel, graphData.YAxisLabel, formattedX, formattedY);
    }
}
