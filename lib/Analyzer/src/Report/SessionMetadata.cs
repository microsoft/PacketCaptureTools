// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Microsoft.PacketCapture.Analyzer.Report;

/// <summary>
/// Analysis report metadata. May contain metadata related to the packet capture, analysis session and/or environment.
/// The metadata will be populated into the rendered report.
/// </summary>
public class SessionMetadata
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SessionMetadata" /> class.
    /// </summary>
    /// <param name="startCaptureTime">The packet capture start time.</param>
    /// <param name="endCaptureTime">The packet capture end time.</param>
    /// <param name="captureAddresses">The IP addresses of the device where the capture was created.</param>
    /// <param name="additionalMetadata">Additional session metadata.</param>
    public SessionMetadata(
        DateTime? startCaptureTime = null,
        DateTime? endCaptureTime = null,
        ISet<IPAddress>? captureAddresses = null,
        IDictionary<string, string>? additionalMetadata = null)
    {
        StartCaptureTime = startCaptureTime;
        EndCaptureTime = endCaptureTime;

        if (captureAddresses == null || captureAddresses.Count == 0)
        {
            try
            {
                captureAddresses = new HashSet<IPAddress>(
                    Dns.GetHostEntry(Dns.GetHostName())
                    .AddressList
                    .Where(address => address.AddressFamily == AddressFamily.InterNetwork || address.AddressFamily == AddressFamily.InterNetworkV6));
            }
            catch (Exception)
            {
                throw new Exception("Failed to retrieve local interface IP addresses. Please provide at least one IP address in the captureAddresses parameter.");
            }

            if (captureAddresses.Count == 0)
            {
                throw new Exception("No local interface IP address found. Please provide at least one IP address in the captureAddresses parameter.");
            }
            
            CaptureAddresses = captureAddresses;
        }
        else
        {
            CaptureAddresses = new HashSet<IPAddress>(captureAddresses);
        }

        if (StartCaptureTime != null &&
            EndCaptureTime != null)
        {
            if (EndCaptureTime < StartCaptureTime)
            {
                throw new ArgumentException($"{nameof(EndCaptureTime)} cannot be a lower value than {nameof(StartCaptureTime)}.");
            }

            CaptureDuration = EndCaptureTime - StartCaptureTime;
        }

        AdditionalMetadata = additionalMetadata ?? new Dictionary<string, string>();
    }

    /// <summary>
    /// Gets the packet capture start time.
    /// </summary>
    public DateTime? StartCaptureTime { get; }

    /// <summary>
    /// Gets the packet capture end time.
    /// </summary>
    public DateTime? EndCaptureTime { get; }

    /// <summary>
    /// Gets the packet capture total duration.
    /// </summary>
    public TimeSpan? CaptureDuration { get; }

    /// <summary>
    /// Gets the IP addresses assigned to the NIC(s) on the capture machine. Packets originating from these IP addresses will be deemed as outgoing.
    /// </summary>
    public IEnumerable<IPAddress> CaptureAddresses { get; }

    /// <summary>
    /// Gets the session additional metadata.
    /// </summary>
    public IDictionary<string, string> AdditionalMetadata { get; }
}
