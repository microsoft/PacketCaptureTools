// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace Microsoft.PacketCapture.Converter.Etl.Reader;

/// <summary>
/// Wrapper around <see cref="EventLogRecord"/> exposing only the properties and methods
/// required by the EventLogAdapters. The reason is to make the <see cref="EventLogRecord"/> testable, as
/// it does not contain a public constructor.
/// </summary>
public interface IEventLogRecordWrapper
{
    /// <summary>
    /// Gets Guid of the etl provider.
    /// </summary>
    Guid? ProviderId { get; }

    /// <summary>
    /// Gets an event Id. A provider might have multiple event types, which are documented by the Id.
    /// </summary>
    int Id { get; }

    /// <summary>
    /// Gets The timestamp at which the event was logged to etl file.
    /// </summary>
    DateTime? TimeCreated { get; }

    /// <summary>
    /// Returns a list of properties fetched by XPath query.
    /// </summary>
    /// <param name="propertySelector">A list of XPath queries.</param>
    /// <returns>A list of fetched properties. An entry in the list is null if it wasn't found.</returns>
    IList<object> GetPropertyValues(EventLogPropertySelector propertySelector);
}
