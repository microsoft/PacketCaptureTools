// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using System;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;

/// <summary>
/// TDS connection latency analysis metrics.
/// </summary>
internal class TdsConnectionLatencyAnalysisMetrics
{
    private DateTime? _preLoginTimestamp;
    private DateTime? _preLoginResponseTimestamp;
    private DateTime? _clientHelloTimestamp;
    private DateTime? _serverHelloTimestamp;
    private DateTime? _keyExchangeTimestamp;
    private DateTime? _cipherChangeTimestamp;
    private DateTime? _loginMessageTimestamp;
    private DateTime? _loginAckTimestamp;
    private DateTime? _latestSuccessfulTcpConnectionStateTimestamp;
    private DateTime? _firstPacketTimestamp;

    /// <summary>
    /// Initializes a new instance of the <see cref="TdsConnectionLatencyAnalysisMetrics" /> class.
    /// </summary>
    /// <param name="tdsConnectionLatencies">TDS connection latencies.</param>
    internal TdsConnectionLatencyAnalysisMetrics(TdsConnectionLatencies? tdsConnectionLatencies = default)
    {
        TdsConnectionLatencies = tdsConnectionLatencies ?? new TdsConnectionLatencies();
    }

    /// <summary>
    /// Gets TDS connection latencies.
    /// </summary>
    internal TdsConnectionLatencies TdsConnectionLatencies { get; }

    /// <summary>
    /// Process TDS state and update metrics.
    /// </summary>
    /// <param name="tdsConnectionSnapshot">TDS connection snapshot.</param>
    /// <param name="timestamp">Timestamp.</param>
    /// <param name="isTdsFailureState">IsTdsFailureState.</param>
    internal void ProcessTdsState(TdsConnectionSnapshot tdsConnectionSnapshot, DateTime timestamp, bool isTdsFailureState)
    {
        TdsConnectionLatencies.LastPacketTimestamp = timestamp;
        TdsConnectionLatencies.TdsConnectionState = tdsConnectionSnapshot.TdsConnectionState;

        if (!_firstPacketTimestamp.HasValue)
        {
            if (tdsConnectionSnapshot.TcpConnectionSnapshot.FirstSynTimestamp.HasValue &&
                tdsConnectionSnapshot.TdsConnectionState.IsTdsPreloginOrPreloginResponse())
            {
                _firstPacketTimestamp = tdsConnectionSnapshot.TcpConnectionSnapshot.FirstSynTimestamp;
            }
            else
            {
                _firstPacketTimestamp = timestamp;
            }
        }

        TdsConnectionLatencies.TotalLatency = timestamp - _firstPacketTimestamp;

        if (_preLoginTimestamp.HasValue)
        {
            TdsConnectionLatencies.PreLoginToLatestStateLatency = timestamp - _preLoginTimestamp;
        }

        if (_latestSuccessfulTcpConnectionStateTimestamp.HasValue)
        {
            TdsConnectionLatencies.LastSuccessfulToLastStateLatency = timestamp - _latestSuccessfulTcpConnectionStateTimestamp;
        }

        if (!isTdsFailureState)
        {
            _latestSuccessfulTcpConnectionStateTimestamp = timestamp;
        }

        if (tdsConnectionSnapshot.TdsConnectionState == TdsConnectionLatencies.LastSuccessfulTdsConnectionState)
        {
            return;
        }

        if (!isTdsFailureState)
        {
            TdsConnectionLatencies.LastSuccessfulTdsConnectionState = tdsConnectionSnapshot.TdsConnectionState;
        }

        switch (tdsConnectionSnapshot.TdsConnectionState)
        {
            case TdsConnectionState.PreLogin:
                _preLoginTimestamp = timestamp;
                if (_firstPacketTimestamp.HasValue)
                {
                    TdsConnectionLatencies.TcpHandshakeToPreLoginLatency = _preLoginTimestamp - _firstPacketTimestamp;
                }

                break;

            case TdsConnectionState.PreLoginResponse:
                _preLoginResponseTimestamp = timestamp;
                if (_preLoginTimestamp.HasValue)
                {
                    TdsConnectionLatencies.PreLoginToPreLoginResponseLatency = _preLoginResponseTimestamp - _preLoginTimestamp;
                }

                break;

            case TdsConnectionState.ClientHello:
                _clientHelloTimestamp = timestamp;
                TdsConnectionLatencies.PreLoginResponseToClientHelloLatency = _clientHelloTimestamp - _preLoginResponseTimestamp;
                break;

            case TdsConnectionState.ServerHello:
                _serverHelloTimestamp = timestamp;
                TdsConnectionLatencies.ClientHelloToServerHelloLatency = _serverHelloTimestamp - _clientHelloTimestamp;
                break;

            case TdsConnectionState.KeyExchange:
                _keyExchangeTimestamp = timestamp;
                TdsConnectionLatencies.ServerHelloToKeyExchangeLatency = _keyExchangeTimestamp - _serverHelloTimestamp;
                break;

            case TdsConnectionState.CipherChange:
                _cipherChangeTimestamp = timestamp;
                TdsConnectionLatencies.KeyExchangeToCipherChangeLatency = _cipherChangeTimestamp - _keyExchangeTimestamp;
                break;

            case TdsConnectionState.LoginMessage:
                _loginMessageTimestamp = timestamp;
                TdsConnectionLatencies.CipherChangeToLoginMessageLatency = _loginMessageTimestamp - _cipherChangeTimestamp;
                break;

            case TdsConnectionState.LoginAck:
                _loginAckTimestamp = timestamp;
                TdsConnectionLatencies.LoginMessageToLoginAckLatency = _loginAckTimestamp - _loginMessageTimestamp;
                break;

            case TdsConnectionState.Unknown:
            default:
                break;
        }
    }
}
