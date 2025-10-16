// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Converter.Etl.Reader;
using Microsoft.PacketCapture.Converter.Packet;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl.Adapter;

/// <summary>
/// An Ndiscap etl event adapter for CapturedPacket.
/// </summary>
[SupportedOSPlatform("windows")]
public class NdiscapEventAdapter : ICapturedPacketAdapter<IEventLogRecordWrapper>
{
    private static readonly DateTime MinEpochTime = new(1970, 1, 1);

    /// <summary>
    /// Converts given EventLogRecord to CapturedPacket if is a valid Ndiscap event.
    /// </summary>
    /// <param name="eventLogRecord">Any EventLogRecord.</param>
    /// <returns>A <see cref="CapturedPacket"/> instance if <paramref name="eventLogRecord"/> is a valid Ndiscap event, otherwise null.</returns>
    public CapturedPacket? Convert(IEventLogRecordWrapper eventLogRecord)
    {
        return IsValidNdiscapEvent(eventLogRecord) ? ParseEventLogRecord(eventLogRecord) : null;
    }

    /// <summary>
    /// Checks whether the provided EventLogRecord is a valid Ndiscap packet.
    /// <br></br><br></br>
    /// Validity means it is:
    /// <list type="number">
    ///     <item>
    ///         <description>Not Null.</description>
    ///     </item>
    ///     <item>
    ///         <description>The Ndiscap provider ID matches the event's provider ID</description>
    ///     </item>
    ///     <item>
    ///         <description>The EventLogRecord ID matches Ndiscap's Fragment Event Id.</description>
    ///     </item>
    /// </list>
    /// </summary>
    /// <param name="eventLogRecord">Any EventLogRecord.</param>
    /// <returns>If the provided etl event is Ndiscap's packet event returns true, otherwise false.</returns>
    private static bool IsValidNdiscapEvent([NotNullWhen(true)] IEventLogRecordWrapper? eventLogRecord)
    {
        if (eventLogRecord == null ||
                            eventLogRecord.ProviderId != NdiscapConstants.NdiscapProviderGuid ||
                            eventLogRecord.Id != NdiscapConstants.NdiscapFragmentEventId)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Converts EventLogRecord to CapturedPacket.
    /// </summary>
    /// <param name="eventLogRecord">Valid EventLogRecord event.</param>
    /// <returns>A CapturedPacket representation of an etl event. In the case the event does not contain necessary parameters, the method returns null.</returns>
    private static CapturedPacket? ParseEventLogRecord(IEventLogRecordWrapper eventLogRecord)
    {
        var timeCaptured = eventLogRecord.TimeCreated ?? MinEpochTime;

        var values = eventLogRecord.GetPropertyValues(NdiscapConstants.NdiscapEvtPropertySelector);
        if (values.Count != NdiscapConstants.NdiscapPropertyXPathQuery.Length)
        {
            return null;
        }

        if (values[0] is not uint capturedPacketSize ||
            values[1] is not byte[] payload)
        {
            return null;
        }

        // Captured packet size is used as an input for original packet size in CapturedPacket
        // as Ndiscap doesn't currently log metadata about truncation in its events. This mechanism
        // might be replaced in the future by inferring the original packet size from IP headers.
        return new CapturedPacket(payload, capturedPacketSize, timeCaptured);
    }
}
