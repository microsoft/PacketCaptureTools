// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Options
{
    /// <summary>
    /// Analysis options.
    /// </summary>
    public class AnalysisOptions
    {
        /// <summary>
        /// Gets the localhost IP address of the device.
        /// </summary>
        public static readonly IPAddress DefaultCaptureAddress = IPAddress.Parse("127.0.0.1");

        /// <summary>
        /// Gets or sets the IP address assigned to the NIC on the capture size. Packets originating from this IP address will be deemed as outgoing in connections.
        /// </summary>
        public IPAddress CaptureAddress { get; set; } = DefaultCaptureAddress;
    }
}
