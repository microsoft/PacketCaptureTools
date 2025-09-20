// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Report.Graph
{
    /// <summary>
    /// Graph data.
    /// </summary>
    public class GraphData
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GraphData" /> class.
        /// </summary>
        /// <param name="xAxisLabel">The label for the graph x-axis.</param>
        /// <param name="yAxisLabel">The label for the graph y-axis.</param>
        /// <param name="xAxisData">The data for the graph x-axis.</param>
        /// <param name="yAxisData">The data for the graph y-axis.</param>
        public GraphData(string xAxisLabel, string yAxisLabel, long[] xAxisData, long[] yAxisData)
        {
            XAxisLabel = xAxisLabel;
            YAxisLabel = yAxisLabel;
            XAxisData = xAxisData;
            YAxisData = yAxisData;
        }

        /// <summary>
        /// Gets the x-axis label.
        /// </summary>
        public string XAxisLabel { get; }

        /// <summary>
        /// Gets the y-axis label.
        /// </summary>
        public string YAxisLabel { get; }

        /// <summary>
        /// Gets the x-axis data.
        /// </summary>
        public long[] XAxisData { get; }

        /// <summary>
        /// Gets the y-axis data.
        /// </summary>
        public long[] YAxisData { get; }
    }
}
