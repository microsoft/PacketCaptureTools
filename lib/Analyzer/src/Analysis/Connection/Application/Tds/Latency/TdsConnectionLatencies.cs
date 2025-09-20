// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using System;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;

/// <summary>
/// TDS connection latencies.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TdsConnectionLatencies" /> class.
/// </remarks>
/// <param name="tdsConnectionState">TDS connection state.</param>
/// <param name="lastSuccessfulTdsConnectionState">Last successful TDS connection state.</param>
/// <param name="tcpHandshakeToPreLoginLatency">TCP handshake to TDS PreLogin latency.</param>
/// <param name="preLoginToPreLoginResponseLatency">PreLogin to PreLoginResponse latency.</param>
/// <param name="preLoginResponseToClientHelloLatency">PreLoginResponse to ClientHello latency.</param>
/// <param name="clientHelloToServerHelloLatency">ClientHello to ServerHello latency.</param>
/// <param name="serverHelloToKeyExchangeLatency">ServerHello to KeyExchange latency.</param>
/// <param name="keyExchangeToCipherChangeLatency">KeyExchange to CipherChange latency.</param>
/// <param name="cipherChangeToLoginMessageLatency">CipherChange to LoginMessage latency.</param>
/// <param name="loginMessageToLoginAckLatency">LoginMessage to LoginAck latency.</param>
/// <param name="preLoginToLatestStateLatency">PreLogin to latest state latency.</param>
/// <param name="lastSuccessfulToLastStateLatency">Last successful to last state latency.</param>
/// <param name="totalLatency">Total connection latency.</param>
/// <param name="lastPacketTimestamp">Last packet timestamp.</param>
public class TdsConnectionLatencies(
    TdsConnectionState tdsConnectionState = TdsConnectionState.Unknown,
    TdsConnectionState lastSuccessfulTdsConnectionState = TdsConnectionState.Unknown,
    TimeSpan? tcpHandshakeToPreLoginLatency = null,
    TimeSpan? preLoginToPreLoginResponseLatency = null,
    TimeSpan? preLoginResponseToClientHelloLatency = null,
    TimeSpan? clientHelloToServerHelloLatency = null,
    TimeSpan? serverHelloToKeyExchangeLatency = null,
    TimeSpan? keyExchangeToCipherChangeLatency = null,
    TimeSpan? cipherChangeToLoginMessageLatency = null,
    TimeSpan? loginMessageToLoginAckLatency = null,
    TimeSpan? preLoginToLatestStateLatency = null,
    TimeSpan? lastSuccessfulToLastStateLatency = null,
    TimeSpan? totalLatency = null,
    DateTime? lastPacketTimestamp = null)
{

    /// <summary>
    /// Gets or sets TDS connection state.
    /// </summary>
    internal TdsConnectionState TdsConnectionState { get; set; } = tdsConnectionState;

    /// <summary>
    /// Gets or sets last successful TDS connection state.
    /// </summary>
    internal TdsConnectionState LastSuccessfulTdsConnectionState { get; set; } = lastSuccessfulTdsConnectionState;

    /// <summary>
    /// Gets or sets TCP handshake to TDS PreLogin latency.
    /// </summary>
    internal TimeSpan? TcpHandshakeToPreLoginLatency { get; set; } = tcpHandshakeToPreLoginLatency;

    /// <summary>
    /// Gets or sets PreLogin to PreLoginResponse latency.
    /// </summary>
    internal TimeSpan? PreLoginToPreLoginResponseLatency { get; set; } = preLoginToPreLoginResponseLatency;

    /// <summary>
    /// Gets or sets PreLoginResponse to ClientHello latency.
    /// </summary>
    internal TimeSpan? PreLoginResponseToClientHelloLatency { get; set; } = preLoginResponseToClientHelloLatency;

    /// <summary>
    /// Gets or sets ClientHello to ServerHello latency.
    /// </summary>
    internal TimeSpan? ClientHelloToServerHelloLatency { get; set; } = clientHelloToServerHelloLatency;

    /// <summary>
    /// Gets or sets ServerHello to KeyExchange latency.
    /// </summary>
    internal TimeSpan? ServerHelloToKeyExchangeLatency { get; set; } = serverHelloToKeyExchangeLatency;

    /// <summary>
    /// Gets or sets KeyExchange to CipherChange latency.
    /// </summary>
    internal TimeSpan? KeyExchangeToCipherChangeLatency { get; set; } = keyExchangeToCipherChangeLatency;

    /// <summary>
    /// Gets or sets CipherChange to LoginMessage latency.
    /// </summary>
    internal TimeSpan? CipherChangeToLoginMessageLatency { get; set; } = cipherChangeToLoginMessageLatency;

    /// <summary>
    /// Gets or sets LoginMessage to LoginAck latency.
    /// </summary>
    internal TimeSpan? LoginMessageToLoginAckLatency { get; set; } = loginMessageToLoginAckLatency;

    /// <summary>
    /// Gets or sets TDS latency between PreLogin and the latest packet.
    /// </summary>
    internal TimeSpan? PreLoginToLatestStateLatency { get; set; } = preLoginToLatestStateLatency;

    /// <summary>
    /// Gets or sets TDS latency between the last successful and the latest packet.
    /// </summary>
    internal TimeSpan? LastSuccessfulToLastStateLatency { get; set; } = lastSuccessfulToLastStateLatency;

    /// <summary>
    /// Gets or sets total latency.
    /// </summary>
    internal TimeSpan? TotalLatency { get; set; } = totalLatency;

    /// <summary>
    /// Gets or sets the latest packet timestamp.
    /// </summary>
    internal DateTime? LastPacketTimestamp { get; set; } = lastPacketTimestamp;
}
