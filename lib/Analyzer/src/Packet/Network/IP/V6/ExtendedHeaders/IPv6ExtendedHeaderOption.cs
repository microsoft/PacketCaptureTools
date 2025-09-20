// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.IP.V6.ExtendedHeaders
{
    /// <summary>
    /// IPv6 Extension Header Option for known options.
    /// </summary>
    public enum IPv6ExtendedHeaderOption
    {
        /// <summary>
        /// Pad 1 option.
        /// </summary>
        Pad1 = 0,

        /// <summary>
        /// Pad N option.
        /// </summary>
        PadN = 1,

        /// <summary>
        /// Tunnel Encapsulation Limit option.
        /// </summary>
        TEL = 4,

        /// <summary>
        /// Router Alert option.
        /// </summary>
        RouterAlert = 5,

        /// <summary>
        /// Common Architecture Label IPv6 Security Option option.
        /// </summary>
        CALIPSO = 7,

        /// <summary>
        /// Simplified Multicast Forwarding Duplicate Packet Detection option.
        /// </summary>
        SMFDPD = 8,

        /// <summary>
        /// Performance and Diagnostic Metrics option.
        /// </summary>
        PDM = 15,

        /// <summary>
        /// IPv6 Routing Protocol for Low-Power and Lossy Networks option.
        /// </summary>
        RPL = 35,

        /// <summary>
        /// Quick Start option.
        /// </summary>
        QuickStart = 38,

        /// <summary>
        /// Path Maximum Transmission Unit Record option.
        /// </summary>
        PathMTURecord = 48,

        /// <summary>
        /// MPL option.
        /// </summary>
        MPL = 109,

        /// <summary>
        /// Identifier-Locator Network Protocol Nonce option.
        /// </summary>
        ILNPNonce = 139,

        /// <summary>
        /// Line-Identification Option option.
        /// </summary>
        LIO = 140,

        /// <summary>
        /// Jumbo Payload option.
        /// </summary>
        JumboPayload = 194,

        /// <summary>
        /// Home Address option.
        /// </summary>
        HomeAddress = 201,

        /// <summary>
        /// IP Depth First Forwarding option.
        /// </summary>
        IPDFF = 238,
    }
}
