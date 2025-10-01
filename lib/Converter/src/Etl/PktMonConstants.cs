// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl;

/// <summary>
/// Pktmon etl provider constants.
/// </summary>
internal static class PktMonConstants
{
    /// <summary>
    /// PktMon Event Payload Id.
    /// </summary>
    public const byte PktMonEvtFramePayloadId = 160;

    /// <summary>
    /// PktMon Dropped Event Payload Id.
    /// </summary>
    public const byte PktMonEvtFrameDropPayloadId = 170;

    /// <summary>
    /// PktMon Etw Provider GUID.
    /// </summary>
    public static readonly Guid PktMonProviderGuid = Guid.Parse("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac");

    /// <summary>
    /// XPath query to extract necessary variables from an EventLogRecord.
    /// </summary>
    public static readonly string[] PktMonPropertyXPathQuery =
    [
        "Event/EventData/Data[@Name='OriginalPayloadSize']",
        "Event/EventData/Data[@Name='Payload']",
    ];

    /// <summary>
    /// PktMon OriginalPayloadSize and Payload property selectors.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static readonly EventLogPropertySelector PktMonEvtPropertySelector = new(PktMonPropertyXPathQuery);
}
