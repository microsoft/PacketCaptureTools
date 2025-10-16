// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace Microsoft.PacketCapture.Converter.Etl.Reader;

/// <summary>
/// Wrapper around <see cref="EventLogRecord"/> exposing only the properties and methods
/// required by the EventLogAdapters.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EventLogRecordWrapper"/> class.
/// </remarks>
/// <param name="eventLogRecord">Instance of <see cref="EventLogRecord"/>.</param>
/// <exception cref="ArgumentNullException">Throws if <paramref name="eventLogRecord"/> is null.</exception>
[SupportedOSPlatform("windows")]
internal class EventLogRecordWrapper(EventLogRecord eventLogRecord) : IEventLogRecordWrapper
{
    private readonly EventLogRecord _eventLogRecord = eventLogRecord ?? throw new ArgumentNullException(nameof(eventLogRecord));

    /// <inheritdoc/>
    public Guid? ProviderId => _eventLogRecord.ProviderId;

    /// <inheritdoc/>
    public int Id => _eventLogRecord.Id;

    /// <inheritdoc/>
    public DateTime? TimeCreated => _eventLogRecord.TimeCreated;

    /// <inheritdoc/>
    public IList<object> GetPropertyValues(EventLogPropertySelector propertySelector)
    {
        return _eventLogRecord.GetPropertyValues(propertySelector);
    }
}
