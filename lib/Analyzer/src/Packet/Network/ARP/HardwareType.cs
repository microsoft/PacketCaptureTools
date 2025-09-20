// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Network.ARP
{
    /// <summary>
    /// Address Resolution Protocol hardware type.
    /// </summary>
    public enum HardwareType
    {
        /// <summary>
        /// Reserved lower-bound value.
        /// </summary>
        Reserved = 0,

        /// <summary>
        /// Ethernet.
        /// </summary>
        Ethernet = 1,
    }
}
