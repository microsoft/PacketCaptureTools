// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl;

/// <summary>
/// Ndiscap etl provider constants.
/// </summary>
internal static class NdiscapConstants
{
    /// <summary>
    /// Ndiscap Fragment Event Id.
    /// </summary>
    public const ushort NdiscapFragmentEventId = 1001;

    /// <summary>
    /// Ndiscap Etw Provider GUID.
    /// </summary>
    public static readonly Guid NdiscapProviderGuid = Guid.Parse("2ed6006e-4729-4609-b423-3ee7bcd678ef");

    /// <summary>
    /// XPath query to extract necessary variables from an EventLogRecord.
    ///
    /// Fragment size is captured packet size. Ndiscap doesn't currently log
    /// metadata about truncation in its events. In the future the original
    /// packet size could be inferred from IP headers.
    /// </summary>
    public static readonly string[] NdiscapPropertyXPathQuery =
      [
          "Event/EventData/Data[@Name='FragmentSize']",
          "Event/EventData/Data[@Name='Fragment']",
      ];

    /// <summary>
    /// Netsh FragmentSize and Fragment property selectors.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static readonly EventLogPropertySelector NdiscapEvtPropertySelector = new(NdiscapPropertyXPathQuery);
}
