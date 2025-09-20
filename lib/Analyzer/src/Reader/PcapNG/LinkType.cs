// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Reader.PcapNG;

/// <summary>
/// Link types.
/// </summary>
public enum LinkType : ushort
{
    /// <summary>
    /// No link layer information. A packet saved with this link layer contains a raw L3 packet preceded by a 32-bit host-byte-order AF_ value indicating the specific L3 type.
    /// </summary>
    Null = 0,

    /// <summary>
    /// D/I/X and 802.3 Ethernet
    /// </summary>
    Ethernet = 1,

    /// <summary>
    /// Experimental Ethernet (3Mb)
    /// </summary>
    ExpEthernet = 2,

    /// <summary>
    /// Raw IP
    /// </summary>
    Raw = 101,
}
