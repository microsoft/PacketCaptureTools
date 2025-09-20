// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP
{
    /// <summary>
    /// IP DSCP value.
    /// </summary>
    public enum DscpValue
    {
        /// <summary>
        /// Unrecognised.
        /// </summary>
        Unrecognised = 0xFF,

        /// <summary>
        /// Network control.
        /// </summary>
        CS6 = 0x30,

        /// <summary>
        /// Telephony.
        /// </summary>
        EF = 0x2E,

        /// <summary>
        /// Signalling.
        /// </summary>
        CS5 = 0x28,

        /// <summary>
        /// Multimedia conferencing type 1.
        /// </summary>
        AF41 = 0x22,

        /// <summary>
        /// Multimedia conferencing type 2.
        /// </summary>
        AF42 = 0x24,

        /// <summary>
        /// Multimedia conferencing type 3.
        /// </summary>
        AF43 = 0x26,

        /// <summary>
        /// Real-time interactive.
        /// </summary>
        CS4 = 0x20,

        /// <summary>
        /// Multimedia streaming type 1.
        /// </summary>
        AF31 = 0x1A,

        /// <summary>
        /// Multimedia streaming type 2.
        /// </summary>
        AF32 = 0x1C,

        /// <summary>
        /// Multimedia streaming type 3.
        /// </summary>
        AF33 = 0x1E,

        /// <summary>
        /// Broadcast video.
        /// </summary>
        CS3 = 0x18,

        /// <summary>
        /// Low-latency data type 1.
        /// </summary>
        AF21 = 0x12,

        /// <summary>
        /// Low-latency data type 2.
        /// </summary>
        AF22 = 0x14,

        /// <summary>
        /// Low-latency data type 3.
        /// </summary>
        AF23 = 0x16,

        /// <summary>
        /// Operations, administration and management (OAM).
        /// </summary>
        CS2 = 0x10,

        /// <summary>
        /// High-throughput data type 1.
        /// </summary>
        AF11 = 0xA,

        /// <summary>
        /// High-throughput data type 2.
        /// </summary>
        AF12 = 0xC,

        /// <summary>
        /// High-throughput data type 3.
        /// </summary>
        AF13 = 0xE,

        /// <summary>
        /// Standard.
        /// </summary>
        DF = 0x0,

        /// <summary>
        /// low-priority data.
        /// </summary>
        CS1 = 0x8,
    }
}
