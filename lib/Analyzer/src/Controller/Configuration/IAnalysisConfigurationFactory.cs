// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Report;
using System;

namespace Microsoft.PacketCapture.Analyzer.Controller.Configuration;

/// <summary>
/// Analysis configuration factory interface.
/// </summary>
public interface IAnalysisConfigurationFactory
{
    /// <summary>
    /// Check whether the <inheritdoc cref="IAnalysisConfigurationFactory" /> has a factory function for a <see cref="key" />.
    /// </summary>
    /// <param name="key">Factory function key.</param>
    /// <returns>True if a key exists, false otherwise.</returns>
    bool ContainsKey(string key);

    /// <summary>
    /// Registers a factory function used to create <see cref="IAnalysisConfiguration" /> of type <see cref="T" />.
    /// </summary>
    /// <typeparam name="T">Type to be created.</typeparam>
    /// <param name="value">Factory function.</param>
    void Register<T>(Func<SessionMetadata, T> value)
        where T : class, IAnalysisConfiguration;

    /// <summary>
    /// Registers a factory function used to create <see cref="IAnalysisConfiguration" />.
    /// </summary>
    /// <param name="key">Function key.</param>
    /// <param name="value">Factory function.</param>
    void Register(string key, Func<SessionMetadata, IAnalysisConfiguration> value);

    /// <summary>
    /// Gets <see cref="IAnalysisConfiguration" /> of type <see cref="T" />.
    /// </summary>
    /// <typeparam name="T">Type to be retrieved.</typeparam>
    /// <param name="sessionMetadata">Session metadata.</param>
    /// <returns><see cref="IAnalysisConfiguration" /> of type <see cref="T" /> with <see cref="SessionMetadata" />.</returns>
    T GetAnalysisConfiguration<T>(SessionMetadata sessionMetadata)
        where T : class, IAnalysisConfiguration;

    /// <summary>
    /// Gets <see cref="IAnalysisConfiguration" /> with key <see cref="key" />.
    /// </summary>
    /// <param name="key">Function key</param>
    /// <param name="sessionMetadata">Session metadata.</param>
    /// <returns><see cref="IAnalysisConfiguration" /> with <see cref="SessionMetadata" />.</returns>
    IAnalysisConfiguration GetAnalysisConfiguration(string key, SessionMetadata sessionMetadata);
}
