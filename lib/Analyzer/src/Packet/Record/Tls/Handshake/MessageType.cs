// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Record.Tls.Handshake
{
    /// <summary>
    /// TLS handshake message type.
    /// </summary>
    public enum MessageType
    {
        /// <summary>
        /// Hello request.
        /// </summary>
        HelloRequest = 0,

        /// <summary>
        /// Client send hello.
        /// </summary>
        ClientHello = 1,

        /// <summary>
        /// Server send hello.
        /// </summary>
        ServerHello = 2,

        /// <summary>
        /// New session ticket.
        /// </summary>
        NewSessionTicket = 3,

        /// <summary>
        /// Encrypted extensions.
        /// </summary>
        EncryptedExtensions = 8,

        /// <summary>
        /// Certificate.
        /// </summary>
        Certificate = 11,

        /// <summary>
        /// Server key-exchange.
        /// </summary>
        ServerKeyExchange = 12,

        /// <summary>
        /// Request certificate.
        /// </summary>
        CertificateRequest = 13,

        /// <summary>
        /// Server hello completed.
        /// </summary>
        ServerHelloDone = 14,

        /// <summary>
        /// Verify certificate.
        /// </summary>
        CertificateVerify = 15,

        /// <summary>
        /// Client key-exchange.
        /// </summary>
        ClientKeyExchange = 16,

        /// <summary>
        /// Finished.
        /// </summary>
        Finished = 20,

        /// <summary>
        /// Unknown message type.
        /// </summary>
        Unknown = 255,
    }
}
