// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;

/// <summary>
/// Metrics for TCP connection counter analysis.
/// </summary>
public class TcpConnectionCounterMetrics
{
    private TimeSpan _cumulativeRoundTripTime;
    private int _countRoundTripTime;

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionCounterMetrics" /> class.
    /// </summary>
    public TcpConnectionCounterMetrics()
        : this(1)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TcpConnectionCounterMetrics" /> class.
    /// </summary>
    /// <param name="uniqueConnectionCount">Unique connection count for the TCP connection.</param>
    /// <param name="cumulativeRoundTripTime">Initial cumulative round trip time.</param>
    /// <param name="countRoundTripTime">Initial count round trip time.</param>
    internal TcpConnectionCounterMetrics(
        int uniqueConnectionCount = 1,
        TimeSpan? cumulativeRoundTripTime = default,
        int countRoundTripTime = 0)
    {
        UniqueConnectionCount = uniqueConnectionCount;
        _cumulativeRoundTripTime = cumulativeRoundTripTime ?? default;
        _countRoundTripTime = countRoundTripTime;
    }

    /// <summary>
    /// Gets or sets the counter for unique connections.
    /// </summary>
    public int UniqueConnectionCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for connection open requests initiated by the client.
    /// </summary>
    public int ClientNewConnectionRequestCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for connection close requests initiated by the client.
    /// </summary>
    public int ClientCloseConnectionRequestCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for connection open requests initiated by the remote source.
    /// </summary>
    public int RemoteNewConnectionRequestCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for connection close requests initiated by the remote source.
    /// </summary>
    public int RemoteCloseConnectionRequestCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for closed connections.
    /// </summary>
    public int ClosedConnectionCount { get; set; }

    /// <summary>
    /// Gets or sets the counter for established connections.
    /// </summary>
    public int EstablishedConnectionCount { get; set; }

    /// <summary>
    /// Gets the average round trip time.
    /// </summary>
    public double AverageRoundTripTime =>
        _countRoundTripTime == 0
            ? 0.0
            : _cumulativeRoundTripTime.TotalSeconds / _countRoundTripTime;

    /// <summary>
    /// Process round trip times for metrics, like calculating average round trip time.
    /// </summary>
    /// <param name="roundTripTime">round trip time value to add.</param>
    public void ProcessRoundTripTime(TimeSpan? roundTripTime)
    {
        if (!roundTripTime.HasValue)
        {
            return;
        }

        _cumulativeRoundTripTime += roundTripTime.Value;
        _countRoundTripTime++;
    }
}
