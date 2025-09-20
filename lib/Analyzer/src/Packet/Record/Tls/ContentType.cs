// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Record.Tls
{
    /// <summary>
    /// TLS record content type field.
    /// </summary>
    public enum ContentType
    {
        /// <summary>
        /// Change cipher strategy.
        /// </summary>
        ChangeCipherSpec = 0x14,

        /// <summary>
        /// Alert.
        /// </summary>
        Alert = 0x15,

        /// <summary>
        /// Handshake.
        /// </summary>
        Handshake = 0x16,

        /// <summary>
        /// Application data.
        /// </summary>
        Application = 0x17,

        /// <summary>
        /// Heartbeat.
        /// </summary>
        Heartbeat = 0x18,
    }
}
