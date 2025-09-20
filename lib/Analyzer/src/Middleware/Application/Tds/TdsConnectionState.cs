// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds
{
    /// <summary>
    /// TDS protocol connection states.
    /// </summary>
    public enum TdsConnectionState
    {
        /// <summary>
        /// Unknown.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// TCP handshake.
        /// </summary>
        TcpHandshake,

        /// <summary>
        /// Pre-login.
        /// </summary>
        PreLogin,

        /// <summary>
        /// Pre-login remote response.
        /// </summary>
        PreLoginResponse,

        /// <summary>
        /// TLS client hello.
        /// </summary>
        ClientHello,

        /// <summary>
        /// TLS server hello.
        /// </summary>
        ServerHello,

        /// <summary>
        /// TLS key exchange.
        /// </summary>
        KeyExchange,

        /// <summary>
        /// TLS cipher change.
        /// </summary>
        CipherChange,

        /// <summary>
        /// Login message sent.
        /// </summary>
        LoginMessage,

        /// <summary>
        /// Login message acknowledged.
        /// </summary>
        LoginAck,

        /// <summary>
        /// Connection closed with error.
        /// </summary>
        ClosedWithError,

        /// <summary>
        /// Connection closed after login ack state.
        /// </summary>
        ConnectionClosedAfterLoginAckTdsState,
    }
}
