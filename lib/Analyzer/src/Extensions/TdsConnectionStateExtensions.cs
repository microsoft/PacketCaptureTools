// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;

namespace Microsoft.PacketCapture.Analyzer.Extensions;

/// <summary>
/// Extensions for TdsConnectionState type.
/// </summary>
internal static class TdsConnectionStateExtensions
{
    private const string TcpHandshake = "TH";
    private const string PreLogin = "PL";
    private const string PreLoginResponse = "PR";
    private const string ClientHello = "CH";
    private const string ServerHello = "SH";
    private const string KeyExchange = "KE";
    private const string CipherChange = "CE";
    private const string LoginMessage = "LM";
    private const string LoginAck = "LR";

    private static readonly string TcpHandshakeOutput = $"{TcpHandshake}";
    private static readonly string PreLoginOutput = $"{TcpHandshakeOutput} -> {PreLogin}";
    private static readonly string PreLoginResponseOutput = $"{PreLoginOutput} -> {PreLoginResponse}";
    private static readonly string ClientHelloOutput = $"{PreLoginResponseOutput} -> {ClientHello}";
    private static readonly string ServerHelloOutput = $"{ClientHelloOutput} -> {ServerHello}";
    private static readonly string KeyExchangeOutput = $"{ServerHelloOutput} -> {KeyExchange}";
    private static readonly string CipherChangeOutput = $"{KeyExchangeOutput} -> {CipherChange}";
    private static readonly string LoginMessageOutput = $"{CipherChangeOutput} -> {LoginMessage}";
    private static readonly string LoginAckOutput = $"{LoginMessageOutput} -> {LoginAck}";

    /// <summary>
    /// Gets two letter abbreviation for TdsConnectionState.
    /// </summary>
    /// <param name="source">TdsConnectionState source.</param>
    /// <returns>TdsConnectionState two letter abbreviation as a string.</returns>
    public static string GetTwoLetterAbbreviation(this TdsConnectionState source)
    {
        switch (source)
        {
            case TdsConnectionState.TcpHandshake:
                return TcpHandshake;

            case TdsConnectionState.PreLogin:
                return PreLogin;

            case TdsConnectionState.PreLoginResponse:
                return PreLoginResponse;

            case TdsConnectionState.ClientHello:
                return ClientHello;

            case TdsConnectionState.ServerHello:
                return ServerHello;

            case TdsConnectionState.KeyExchange:
                return KeyExchange;

            case TdsConnectionState.CipherChange:
                return CipherChange;

            case TdsConnectionState.LoginMessage:
                return LoginMessage;

            case TdsConnectionState.LoginAck:
                return LoginAck;

            default:
                return string.Empty;
        }
    }

    /// <summary>
    /// Gets TDS login steps completed from <see cref="TdsConnectionState" />.
    /// </summary>
    /// <param name="source">Source.</param>
    /// <returns>TDS login steps completed as a string.</returns>
    public static string GetLoginStepsCompleted(this TdsConnectionState source)
    {
        switch (source)
        {
            case TdsConnectionState.TcpHandshake:
                return TcpHandshakeOutput;

            case TdsConnectionState.PreLogin:
                return PreLoginOutput;

            case TdsConnectionState.PreLoginResponse:
                return PreLoginResponseOutput;

            case TdsConnectionState.ClientHello:
                return ClientHelloOutput;

            case TdsConnectionState.ServerHello:
                return ServerHelloOutput;

            case TdsConnectionState.KeyExchange:
                return KeyExchangeOutput;

            case TdsConnectionState.CipherChange:
                return CipherChangeOutput;

            case TdsConnectionState.LoginMessage:
                return LoginMessageOutput;

            case TdsConnectionState.LoginAck:
                return LoginAckOutput;

            default:
                return string.Empty;
        }
    }

    /// <summary>
    /// Check whether TDS connection finished with success.
    /// </summary>
    /// <param name="tdsConnectionState">TDS connection state.</param>
    /// <returns>True if TDS connection is in finished with success, false otherwise.</returns>
    internal static bool IsTdsConnectionFinishedWithSuccess(this TdsConnectionState tdsConnectionState) =>
        tdsConnectionState == TdsConnectionState.LoginAck ||
        tdsConnectionState == TdsConnectionState.ConnectionClosedAfterLoginAckTdsState;

    /// <summary>
    /// Check whether TDS connection is closed.
    /// </summary>
    /// <param name="tdsConnectionState">TDS connection state.</param>
    /// <returns>True if TDS connection is closed, false otherwise.</returns>
    internal static bool IsTdsConnectionClosed(this TdsConnectionState tdsConnectionState) =>
        tdsConnectionState == TdsConnectionState.ClosedWithError ||
        tdsConnectionState == TdsConnectionState.ConnectionClosedAfterLoginAckTdsState;

    /// <summary>
    /// Check whether TDS connection is in finished state.
    /// </summary>
    /// <param name="tdsConnectionState">TDS connection state.</param>
    /// <returns>True if TDS connection is in finished state, false otherwise.</returns>
    internal static bool IsTdsConnectionInFinishedState(this TdsConnectionState tdsConnectionState) =>
        tdsConnectionState == TdsConnectionState.LoginAck ||
        tdsConnectionState == TdsConnectionState.ClosedWithError ||
        tdsConnectionState == TdsConnectionState.ConnectionClosedAfterLoginAckTdsState;

    /// <summary>
    /// Check whether TDS connection is in prelogin or prelogin response state.
    /// </summary>
    /// <param name="tdsConnectionState">TDS connection state.</param>
    /// <returns>True if TDS connection is prelogin or prelogin response state, false otherwise.</returns>
    internal static bool IsTdsPreloginOrPreloginResponse(this TdsConnectionState tdsConnectionState) =>
        tdsConnectionState == TdsConnectionState.PreLogin ||
        tdsConnectionState == TdsConnectionState.PreLoginResponse;
}
