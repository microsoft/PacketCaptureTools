// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using System;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;

/// <summary>
/// TDS login connection metrics.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsLoginConnectionMetrics" /> class.
/// </remarks>
/// <param name="startFrameNumber">The first seen frame number of the connection.</param>
/// <param name="endFrameNumber">The last seen frame number of the connection.</param>
/// <param name="totalSeenPackets">The total number of packets seen in the connection.</param>
/// <param name="firstCapturedTime">The captured time of the first seen packet.</param>
/// <param name="lastCapturedTime">The captured time of the last seen packet.</param>
/// <param name="connectionState">The last seen connection state.</param>
/// <param name="lastSuccessfulConnectionState">The last seen successful connection state.</param>
public class TdsLoginConnectionMetrics(
    int startFrameNumber,
    int endFrameNumber,
    int totalSeenPackets,
    DateTime firstCapturedTime,
    DateTime lastCapturedTime,
    TdsConnectionState connectionState,
    TdsConnectionState lastSuccessfulConnectionState)
{

    /// <summary>
    /// Gets the first seen frame number of the connection.
    /// </summary>
    public int StartFrameNumber { get; } = startFrameNumber;

    /// <summary>
    /// Gets the last seen frame number of the connection.
    /// </summary>
    public int EndFrameNumber { get; } = endFrameNumber;

    /// <summary>
    /// Gets the last seen frame number of the connection.
    /// </summary>
    public int TotalSeenPackets { get; } = totalSeenPackets;

    /// <summary>
    /// Gets the duration of the TDS connection.
    /// </summary>
    public TimeSpan ConnectionDuration => LastCapturedTime - FirstCapturedTime;

    /// <summary>
    /// Gets the captured time of the first seen packet.
    /// </summary>
    public DateTime FirstCapturedTime { get; } = firstCapturedTime;

    /// <summary>
    /// Gets the captured time of the last seen packet.
    /// </summary>
    public DateTime LastCapturedTime { get; } = lastCapturedTime;

    /// <summary>
    /// Gets the last seen connection state.
    /// </summary>
    public TdsConnectionState ConnectionState { get; } = connectionState;

    /// <summary>
    /// Gets the last successful connection state.
    /// </summary>
    public TdsConnectionState LastSuccessfulConnectionState { get; } = lastSuccessfulConnectionState;
}
