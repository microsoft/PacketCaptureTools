// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;

/// <summary>
/// TDS connection latency analysis.
/// </summary>
public class TdsConnectionLatencyAnalysis : TdsConnectionAnalysis
{
    private readonly Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>> _connectionMetrics;
    private readonly Dictionary<DateTime, TimestampMetrics> _tcpEstablishedToPreLoginLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _preLoginToPreLoginResponseLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _preLoginResponseToClientHelloLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _clientHelloToServerHelloLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _serverHelloToKeyExchangeAckLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _keyExchangeToCipherChangeLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _cipherChangeToLoginMessageLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _loginMessageToLoginAckLatencies;
    private readonly Dictionary<DateTime, TimestampMetrics> _preLoginToLoginAckLatencies;

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionLatencyAnalysis" /> class.
    /// </summary>
    public TdsConnectionLatencyAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionLatencyAnalysis" /> class.
    /// </summary>
    /// <param name="tcpEstablishedToPreLoginLatencies">Initial TcpEstablishedToPreLoginLatencies dictionary.</param>
    /// <param name="preLoginToPreLoginResponseLatencies">Initial PreLoginToPreLoginResponseLatencies dictionary.</param>
    /// <param name="preLoginResponseToClientHelloLatencies">Initial PreLoginResponseToClientHelloLatencies dictionary.</param>
    /// <param name="clientHelloToServerHelloLatencies">Initial ClientHelloToServerHelloLatencies dictionary.</param>
    /// <param name="serverHelloToKeyExchangeLatencies">Initial ServerHelloToKeyExchangeLatencies dictionary.</param>
    /// <param name="keyExchangeToCipherChangeLatencies">Initial KeyExchangeToCipherChangeLatencies dictionary.</param>
    /// <param name="cipherChangeToLoginMessageLatencies">Initial CipherChangeToLoginMessageLatencies dictionary.</param>
    /// <param name="loginMessageToLoginAckLatencies">Initial LoginMessageToLoginAckLatencies dictionary.</param>
    /// <param name="preLoginToLoginAckLatencies">Initial PreLoginToLoginAckLatencies dictionary.</param>
    /// <param name="tcpHandshakeToPreLoginAverageLatencies">Initial TcpEstablishedToPreLoginAverageLatencies dictionary.</param>
    /// <param name="preLoginToPreLoginResponseAverageLatencies">Initial PreLoginToPreLoginResponseAverageLatencies dictionary.</param>
    /// <param name="preLoginResponseToClientHelloAverageLatencies">Initial PreLoginResponseToClientHelloAverageLatencies dictionary.</param>
    /// <param name="clientHelloToServerHelloAverageLatencies">Initial ClientHelloToServerHelloAverageLatencies dictionary.</param>
    /// <param name="serverHelloToKeyExchangeAverageLatencies">Initial ServerHelloToKeyExchangeAverageLatencies dictionary.</param>
    /// <param name="keyExchangeToCipherChangeAverageLatencies">Initial KeyExchangeToCipherChangeAverageLatencies dictionary.</param>
    /// <param name="cipherChangeToLoginMessageAverageLatencies">Initial CipherChangeToLoginMessageAverageLatencies dictionary.</param>
    /// <param name="loginMessageToLoginAckAverageLatencies">Initial LoginMessageToLoginAckAverageLatencies dictionary.</param>
    /// <param name="preLoginToLoginAckAverageLatencies">Initial PreLoginToLoginAckAverageLatencies dictionary.</param>
    /// <param name="tdsConnectionLatencyAnalysisMetrics">Initial TdsConnectionLatencyAnalysisMetrics dictionary.</param>
    internal TdsConnectionLatencyAnalysis(
        Dictionary<DateTime, TimestampMetrics>? tcpEstablishedToPreLoginLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? preLoginToPreLoginResponseLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? preLoginResponseToClientHelloLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? clientHelloToServerHelloLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? serverHelloToKeyExchangeLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? keyExchangeToCipherChangeLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? cipherChangeToLoginMessageLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? loginMessageToLoginAckLatencies = default,
        Dictionary<DateTime, TimestampMetrics>? preLoginToLoginAckLatencies = default,
        Dictionary<DateTime, TimeSpan>? tcpHandshakeToPreLoginAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? preLoginToPreLoginResponseAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? preLoginResponseToClientHelloAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? clientHelloToServerHelloAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? serverHelloToKeyExchangeAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? keyExchangeToCipherChangeAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? cipherChangeToLoginMessageAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? loginMessageToLoginAckAverageLatencies = default,
        Dictionary<DateTime, TimeSpan>? preLoginToLoginAckAverageLatencies = default,
        Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>>? tdsConnectionLatencyAnalysisMetrics = default)
    {
        _connectionMetrics = tdsConnectionLatencyAnalysisMetrics ?? new Dictionary<TransportLayerConnection, List<TdsConnectionLatencyAnalysisMetrics>>();

        _tcpEstablishedToPreLoginLatencies = tcpEstablishedToPreLoginLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _preLoginToPreLoginResponseLatencies = preLoginToPreLoginResponseLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _preLoginResponseToClientHelloLatencies = preLoginResponseToClientHelloLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _clientHelloToServerHelloLatencies = clientHelloToServerHelloLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _serverHelloToKeyExchangeAckLatencies = serverHelloToKeyExchangeLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _keyExchangeToCipherChangeLatencies = keyExchangeToCipherChangeLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _cipherChangeToLoginMessageLatencies = cipherChangeToLoginMessageLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _loginMessageToLoginAckLatencies = loginMessageToLoginAckLatencies ?? new Dictionary<DateTime, TimestampMetrics>();
        _preLoginToLoginAckLatencies = preLoginToLoginAckLatencies ?? new Dictionary<DateTime, TimestampMetrics>();

        TcpHandshakeToPreLoginAverageLatencies = tcpHandshakeToPreLoginAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        PreLoginToPreLoginResponseAverageLatencies = preLoginToPreLoginResponseAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        PreLoginResponseToClientHelloAverageLatencies = preLoginResponseToClientHelloAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        ClientHelloToServerHelloAverageLatencies = clientHelloToServerHelloAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        ServerHelloToKeyExchangeAverageLatencies = serverHelloToKeyExchangeAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        KeyExchangeToCipherChangeAverageLatencies = keyExchangeToCipherChangeAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        CipherChangeToLoginMessageAverageLatencies = cipherChangeToLoginMessageAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        LoginMessageToLoginAckAverageLatencies = loginMessageToLoginAckAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
        PreLoginToLoginAckAverageLatencies = preLoginToLoginAckAverageLatencies ?? new Dictionary<DateTime, TimeSpan>();
    }

    /// <summary>
    /// Gets TCP established -> TDS PreLogin average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> TcpHandshakeToPreLoginAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection PreLogin -> PreLoginResponse average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> PreLoginToPreLoginResponseAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection PreLoginResponse -> ClientHello average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> PreLoginResponseToClientHelloAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection ClientHello -> ServerHello average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> ClientHelloToServerHelloAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection ServerHello -> KeyExchange average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> ServerHelloToKeyExchangeAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection KeyExchange -> CipherChange average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> KeyExchangeToCipherChangeAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection CipherChange -> LoginMessage average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> CipherChangeToLoginMessageAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection LoginMessage -> LoginAck average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> LoginMessageToLoginAckAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection PreLogin -> LoginAck average latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> PreLoginToLoginAckAverageLatencies { get; }

    /// <summary>
    /// Gets TDS connection latencies for failed TDS connections.
    /// </summary>
    public Dictionary<TransportLayerConnection, List<TdsConnectionLatencies>> FailedTdsConnectionMetrics => GetFailedTdsConnectionMetrics();

    /// <summary>
    /// Gets TDS connection latencies.
    /// </summary>
    public Dictionary<DateTime, TimeSpan> TdsConnectionLatencies => GetTdsConnectionLatencies();

    /// <inheritdoc />
    public override void Process(CapturedPacket packet, TdsConnectionSnapshot tdsConnectionSnapshot)
    {
        if (packet?.CapturedDateTime is not DateTime packetTimestamp ||
            tdsConnectionSnapshot.TransportConnectionSnapshot is not TcpConnectionSnapshot tcpConnectionSnapshot ||
            tdsConnectionSnapshot.TdsConnectionState == TdsConnectionState.Unknown)
        {
            return;
        }

        var isFailedTdsConnection = IsFailedTdsConnection(tdsConnectionSnapshot, tcpConnectionSnapshot);

        if (IsNewConnectionState(tdsConnectionSnapshot))
        {
            _connectionMetrics.AddToList(
                key: tdsConnectionSnapshot.TransportConnection,
                value: new TdsConnectionLatencyAnalysisMetrics());
        }

        var metrics = _connectionMetrics[tdsConnectionSnapshot.TransportConnection].Last();
        var previousTdsState = metrics.TdsConnectionLatencies.LastSuccessfulTdsConnectionState;

        metrics.ProcessTdsState(tdsConnectionSnapshot, packetTimestamp, isFailedTdsConnection);

        if (tdsConnectionSnapshot.TdsConnectionState != previousTdsState)
        {
            HandleTdsConnectionState(tdsConnectionSnapshot, metrics, packetTimestamp.TruncateToSeconds());
        }
    }

    private bool IsNewConnectionState(TdsConnectionSnapshot snapshot)
    {
        return !_connectionMetrics.ContainsKey(snapshot.TransportConnection) ||
               (_connectionMetrics[snapshot.TransportConnection].Last().TdsConnectionLatencies.TdsConnectionState.IsTdsConnectionClosed() &&
                !snapshot.TdsConnectionState.IsTdsConnectionClosed());
    }

    private bool IsFailedTdsConnection(TdsConnectionSnapshot tdsConnectionSnapshot, TcpConnectionSnapshot tcpConnectionSnapshot)
    {
        // TCP connection no longer established while TDS process hasn't finished
        if (!tcpConnectionSnapshot.IsConnectionInTcpHandshakeOrEstablishedConnectionState &&
            !tdsConnectionSnapshot.TdsConnectionState.IsTdsConnectionInFinishedState())
        {
            return true;
        }

        if (tdsConnectionSnapshot.TdsConnectionState == TdsConnectionState.ClosedWithError)
        {
            return true;
        }

        // TDS connection state isn't in finished state and TDS connection state is lower than the last seen on the existing connection
        return !tdsConnectionSnapshot.TdsConnectionState.IsTdsConnectionInFinishedState() &&
               _connectionMetrics.ContainsKey(tdsConnectionSnapshot.TransportConnection) &&
               tdsConnectionSnapshot.TdsConnectionState < _connectionMetrics[tdsConnectionSnapshot.TransportConnection].Last().TdsConnectionLatencies.TdsConnectionState;
    }

    private Dictionary<DateTime, TimeSpan> GetTdsConnectionLatencies()
    {
        var totalLatencies = new Dictionary<DateTime, TimestampMetrics>();

        var connectionMetrics = _connectionMetrics.Values
            .SelectMany(x => x)
            .Where(l => l.TdsConnectionLatencies.LastPacketTimestamp.HasValue && l.TdsConnectionLatencies.TotalLatency.HasValue)
            .ToList();

        foreach (var connectionMetric in connectionMetrics)
        {
            totalLatencies.InsertIntoMetrics(connectionMetric.TdsConnectionLatencies.LastPacketTimestamp!.Value, connectionMetric.TdsConnectionLatencies.TotalLatency!.Value);
        }

        return connectionMetrics
            .Where(x => x.TdsConnectionLatencies.LastPacketTimestamp.HasValue)
            .Select(x => x.TdsConnectionLatencies.LastPacketTimestamp)
            .Distinct()
            .ToDictionary(lastPacketTimestamp => lastPacketTimestamp!.Value, lastPacketTimestamp => totalLatencies[lastPacketTimestamp!.Value].Average);
    }

    private Dictionary<DateTime, TimeSpan> GetFailedTdsConnectionLatencies()
    {
        var failedConnectionLatencies = GetFailedTdsConnectionMetrics()
            .Values
            .SelectMany(tdsConnectionLatenciesList => tdsConnectionLatenciesList
                .Select(l => new KeyValuePair<DateTime?, TimeSpan?>(l.LastPacketTimestamp, l.TotalLatency)))
            .Where(kvp => kvp.Key.HasValue && kvp.Value.HasValue)
            .ToDictionary(x => x.Key!.Value, x => x.Value!.Value);

        return failedConnectionLatencies;
    }

    private Dictionary<TransportLayerConnection, List<TdsConnectionLatencies>> GetFailedTdsConnectionMetrics()
    {
        var failedTdsConnectionMetrics = new Dictionary<TransportLayerConnection, List<TdsConnectionLatencies>>();

        foreach (var connectionMetrics in _connectionMetrics.Select(kvp => (kvp.Key, kvp.Value.Where(connectionMetric => !connectionMetric.TdsConnectionLatencies.TdsConnectionState.IsTdsConnectionFinishedWithSuccess()))))
        {
            foreach (var tdsConnectionLatencyMetrics in connectionMetrics.Item2)
            {
                failedTdsConnectionMetrics.AddToList(connectionMetrics.Key, tdsConnectionLatencyMetrics.TdsConnectionLatencies);
            }
        }

        return failedTdsConnectionMetrics;
    }

    private void HandleTdsConnectionState(TdsConnectionSnapshot tdsConnectionSnapshot, TdsConnectionLatencyAnalysisMetrics metrics, DateTime truncatedPacketTimestamp)
    {
        switch (tdsConnectionSnapshot.TdsConnectionState)
        {
            case TdsConnectionState.PreLogin:
                HandlePreLoginState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.PreLoginResponse:
                HandlePreLoginResponseState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.ClientHello:
                HandleClientHelloState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.ServerHello:
                HandleServerHelloState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.KeyExchange:
                HandleKeyExchangeState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.CipherChange:
                HandleCipherChangeState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.LoginMessage:
                HandleLoginMessageState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;

            case TdsConnectionState.LoginAck:
                HandleLoginAckState(metrics.TdsConnectionLatencies, truncatedPacketTimestamp);
                break;
        }
    }

    private void HandlePreLoginState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.TcpHandshakeToPreLoginLatency is not TimeSpan tcpHandshakeSuccessToPreLoginToPreLoginLatency)
        {
            return;
        }

        _tcpEstablishedToPreLoginLatencies.InsertIntoMetrics(packetTimestamp, tcpHandshakeSuccessToPreLoginToPreLoginLatency);
        TcpHandshakeToPreLoginAverageLatencies[packetTimestamp] = _tcpEstablishedToPreLoginLatencies[packetTimestamp].Average;
    }

    private void HandlePreLoginResponseState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.PreLoginToPreLoginResponseLatency is not TimeSpan preLoginLatency)
        {
            return;
        }

        _preLoginToPreLoginResponseLatencies.InsertIntoMetrics(packetTimestamp, preLoginLatency);
        PreLoginToPreLoginResponseAverageLatencies[packetTimestamp] = _preLoginToPreLoginResponseLatencies[packetTimestamp].Average;
    }

    private void HandleClientHelloState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.PreLoginResponseToClientHelloLatency is null)
        {
            return;
        }

        _preLoginResponseToClientHelloLatencies.InsertIntoMetrics(packetTimestamp, latencies.PreLoginResponseToClientHelloLatency.Value);
        PreLoginResponseToClientHelloAverageLatencies[packetTimestamp] = _preLoginResponseToClientHelloLatencies[packetTimestamp].Average;
    }

    private void HandleServerHelloState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.ClientHelloToServerHelloLatency is null)
        {
            return;
        }

        _clientHelloToServerHelloLatencies.InsertIntoMetrics(packetTimestamp, latencies.ClientHelloToServerHelloLatency.Value);
        ClientHelloToServerHelloAverageLatencies[packetTimestamp] = _clientHelloToServerHelloLatencies[packetTimestamp].Average;
    }

    private void HandleKeyExchangeState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.ServerHelloToKeyExchangeLatency is null)
        {
            return;
        }

        _serverHelloToKeyExchangeAckLatencies.InsertIntoMetrics(packetTimestamp, latencies.ServerHelloToKeyExchangeLatency.Value);
        ServerHelloToKeyExchangeAverageLatencies[packetTimestamp] = _serverHelloToKeyExchangeAckLatencies[packetTimestamp].Average;
    }

    private void HandleCipherChangeState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.KeyExchangeToCipherChangeLatency is null)
        {
            return;
        }

        _keyExchangeToCipherChangeLatencies.InsertIntoMetrics(packetTimestamp, latencies.KeyExchangeToCipherChangeLatency.Value);
        KeyExchangeToCipherChangeAverageLatencies[packetTimestamp] = _keyExchangeToCipherChangeLatencies[packetTimestamp].Average;
    }

    private void HandleLoginMessageState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.CipherChangeToLoginMessageLatency is null)
        {
            return;
        }

        _cipherChangeToLoginMessageLatencies.InsertIntoMetrics(packetTimestamp, latencies.CipherChangeToLoginMessageLatency.Value);
        CipherChangeToLoginMessageAverageLatencies[packetTimestamp] = _cipherChangeToLoginMessageLatencies[packetTimestamp].Average;
    }

    private void HandleLoginAckState(TdsConnectionLatencies latencies, DateTime packetTimestamp)
    {
        if (latencies.LoginMessageToLoginAckLatency != null)
        {
            _loginMessageToLoginAckLatencies.InsertIntoMetrics(packetTimestamp, latencies.LoginMessageToLoginAckLatency.Value);
            LoginMessageToLoginAckAverageLatencies[packetTimestamp] = _loginMessageToLoginAckLatencies[packetTimestamp].Average;
        }

        if (latencies.PreLoginToLatestStateLatency != null)
        {
            _preLoginToLoginAckLatencies.InsertIntoMetrics(packetTimestamp, latencies.PreLoginToLatestStateLatency.Value);
            PreLoginToLoginAckAverageLatencies[packetTimestamp] = _preLoginToLoginAckLatencies[packetTimestamp].Average;
        }
    }
}
