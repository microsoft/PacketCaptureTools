// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;

/// <summary>
/// TDS login connection analysis.
/// </summary>
public class TdsLoginConnectionAnalysis : TdsConnectionAnalysis
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TdsLoginConnectionAnalysis" /> class.
    /// </summary>
    public TdsLoginConnectionAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsLoginConnectionAnalysis" /> class.
    /// </summary>
    /// <param name="connectionStates">The TDS connection states.</param>
    internal TdsLoginConnectionAnalysis(Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>>? connectionStates = default)
    {
        ConnectionStates = connectionStates ?? [];
    }

    /// <summary>
    /// Gets the login connection states.
    /// </summary>
    public Dictionary<TransportLayerConnection, List<TdsLoginConnectionMetrics>> ConnectionStates { get; }

    /// <inheritdoc />
    public override void Process(CapturedPacket packet, TdsConnectionSnapshot tdsConnectionSnapshot)
    {
        if (packet?.CapturedDateTime is null ||
            tdsConnectionSnapshot is null ||
            tdsConnectionSnapshot.TdsConnectionState == TdsConnectionState.Unknown)
        {
            return;
        }

        var tcpConnection = tdsConnectionSnapshot.TransportConnection;

        if (IsNewConnectionState(tdsConnectionSnapshot, tcpConnection))
        {
            AddNewConnectionState(packet, tdsConnectionSnapshot, tcpConnection);

            return;
        }

        UpdateLastConnectionState(packet, tdsConnectionSnapshot, tcpConnection);
    }

    /// <summary>
    /// Gets the current successful connections aggregated by network connection.
    /// </summary>
    /// <returns>A dictionary of successful connections by network connection.</returns>
    public Dictionary<NetworkLayerConnection, int> GetSuccessfulConnectionsByNetworkConnection()
    {
        var successfulConnections = new Dictionary<NetworkLayerConnection, int>();

        foreach (var connectionState in ConnectionStates)
        {
            foreach (var tdsLoginConnectionMetric in connectionState.Value)
            {
                var aggregateKey = new NetworkLayerConnection(connectionState.Key.SourceIpAddress, connectionState.Key.DestinationIpAddress);

                if (!successfulConnections.ContainsKey(aggregateKey))
                {
                    successfulConnections[aggregateKey] = 0;
                }

                if (tdsLoginConnectionMetric.ConnectionState.IsTdsConnectionFinishedWithSuccess())
                {
                    var seenCount = successfulConnections.TryGetValue(aggregateKey, out int value) ? value + 1 : 1;
                    successfulConnections[aggregateKey] = seenCount;
                }
            }
        }

        return successfulConnections;
    }

    /// <summary>
    /// Gets the current failed connections aggregated by network connection.
    /// </summary>
    /// <param name="networkLayerConnection">The network layer connection.</param>
    /// <returns>A dictionary of successful connections by network connection.</returns>
    public Dictionary<TdsConnectionState, int> GetFailedConnectionStatesByConnection(NetworkLayerConnection networkLayerConnection)
    {
        var failedConnectionStates = new Dictionary<TdsConnectionState, int>
        {
            { TdsConnectionState.TcpHandshake, 0 },
            { TdsConnectionState.PreLogin, 0 },
            { TdsConnectionState.PreLoginResponse, 0 },
            { TdsConnectionState.ClientHello, 0 },
            { TdsConnectionState.ServerHello, 0 },
            { TdsConnectionState.KeyExchange, 0 },
            { TdsConnectionState.CipherChange, 0 },
            { TdsConnectionState.LoginMessage, 0 },
        };

        foreach (var connectionState in ConnectionStates
                     .Where(kvp => kvp.Key.IsSameConnection(networkLayerConnection, out _))
                     .Select(kvp => (kvp.Key, kvp.Value
                             .Where(connectionMetric => !connectionMetric.ConnectionState.IsTdsConnectionFinishedWithSuccess()))))
        {
            foreach (var metrics in connectionState.Item2)
            {
                failedConnectionStates[metrics.LastSuccessfulConnectionState] = failedConnectionStates.TryGetValue(metrics.LastSuccessfulConnectionState, out int value)
                    ? value + 1
                    : 1;
            }
        }

        return failedConnectionStates;
    }

    /// <summary>
    /// Gets the number of failed TDS login connections by time.
    /// </summary>
    /// <returns>A dictionary containing TDS connection times and the number of failed connections.</returns>
    public Dictionary<DateTime, int> GetNumberOfFailedTdsConnectionsByTime()
    {
        var failedConnectionStatesByTime = new Dictionary<DateTime, int>();

        foreach (var connectionState in ConnectionStates)
        {
            foreach (var tdsLoginConnectionMetric in connectionState.Value)
            {
                var failedConnectionCounter = !tdsLoginConnectionMetric.ConnectionState.IsTdsConnectionFinishedWithSuccess() ? 1 : 0;
                var capturedTimeSecond = tdsLoginConnectionMetric.LastCapturedTime.TruncateToSeconds();

                if (!failedConnectionStatesByTime.TryAdd(capturedTimeSecond, failedConnectionCounter))
                {
                    failedConnectionStatesByTime[capturedTimeSecond] += failedConnectionCounter;
                }
            }
        }

        return failedConnectionStatesByTime;
    }

    private bool IsNewConnectionState(TdsConnectionSnapshot tdsConnectionSnapshot, TransportLayerConnection tcpConnection)
    {
        return !ConnectionStates.ContainsKey(tdsConnectionSnapshot.TransportConnection) ||
               (ConnectionStates[tcpConnection].Last().ConnectionState.IsTdsConnectionClosed() &&
                !tdsConnectionSnapshot.TdsConnectionState.IsTdsConnectionClosed());
    }

    private void AddNewConnectionState(CapturedPacket packet, TdsConnectionSnapshot tdsConnectionSnapshot, TransportLayerConnection tcpConnection)
    {
        var lastSuccessfulConnectionState = tdsConnectionSnapshot.TdsConnectionState == TdsConnectionState.ClosedWithError
            ? TdsConnectionState.Unknown
            : tdsConnectionSnapshot.TdsConnectionState;

        ConnectionStates.AddToList(
            key: tcpConnection,
            value: new TdsLoginConnectionMetrics(
                startFrameNumber: packet.FrameNumber,
                endFrameNumber: packet.FrameNumber,
                totalSeenPackets: tdsConnectionSnapshot.TcpConnectionSnapshot.TotalConnectionPackets,
                firstCapturedTime: packet.CapturedDateTime ?? DateTime.UnixEpoch,
                lastCapturedTime: packet.CapturedDateTime ?? DateTime.UnixEpoch,
                connectionState: tdsConnectionSnapshot.TdsConnectionState,
                lastSuccessfulConnectionState: lastSuccessfulConnectionState));
    }

    private void UpdateLastConnectionState(CapturedPacket packet, TdsConnectionSnapshot tdsConnectionSnapshot, TransportLayerConnection tcpConnection)
    {
        var lastSuccessfulConnectionState = tdsConnectionSnapshot.TdsConnectionState == TdsConnectionState.ClosedWithError
            ? ConnectionStates[tcpConnection].Last().LastSuccessfulConnectionState
            : tdsConnectionSnapshot.TdsConnectionState;

        ConnectionStates[tcpConnection][^1] = new TdsLoginConnectionMetrics(
            startFrameNumber: ConnectionStates[tcpConnection].Last().StartFrameNumber,
            endFrameNumber: packet.FrameNumber,
            totalSeenPackets: tdsConnectionSnapshot.TcpConnectionSnapshot.TotalConnectionPackets,
            firstCapturedTime: ConnectionStates[tcpConnection].Last().FirstCapturedTime,
            lastCapturedTime: packet.CapturedDateTime ?? DateTime.UnixEpoch,
            connectionState: tdsConnectionSnapshot.TdsConnectionState,
            lastSuccessfulConnectionState: lastSuccessfulConnectionState);
    }
}
