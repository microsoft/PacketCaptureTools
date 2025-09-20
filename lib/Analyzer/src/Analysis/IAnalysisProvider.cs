using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis;

/// <summary>
/// Defines a contract for providing access to analysis.
/// </summary>
public interface IAnalysisProvider
{
    /// <summary>
    /// Retrieves a packet analysis instance of the specified type, if available.
    /// </summary>
    /// <typeparam name="T">The type of packet analysis to retrieve. Must implement the IPacketAnalysis interface.</typeparam>
    /// <returns>An instance of the specified packet analysis type if it is registered; otherwise, null.</returns>
    T? GetPacketAnalysis<T>() where T : IPacketAnalysis;

    /// <summary>
    /// Retrieves a required packet analysis instance of the specified type. Throws an exception if no instance is
    /// found.
    /// </summary>
    /// <typeparam name="T">The type of packet analysis to retrieve. Must implement the IPacketAnalysis interface.</typeparam>
    /// <returns>An instance of the specified packet analysis type.</returns>
    /// <exception cref="Exception">Thrown if no packet analysis instance is found for the specified type.</exception>
    T GetRequiredPacketAnalysis<T>() where T : IPacketAnalysis
    {
        return GetPacketAnalysis<T>() ?? throw new Exception($"No Packet analysis found for the type {typeof(T).Name}");
    }

    /// <summary>
    /// Retrieves a transport layer connection analysis instance of the specified type, if available.
    /// </summary>
    /// <typeparam name="T">The type of transport layer connection analysis to retrieve. Must implement ITransportLayerConnectionAnalysis.</typeparam>
    /// <returns>An instance of the specified transport layer connection analysis type if available; otherwise, null.</returns>
    T? GetTransportLayerConnectionAnalysis<T>() where T : ITransportLayerConnectionAnalysis;

    /// <summary>
    /// Retrieves a required transport layer connection analysis of the specified type.
    /// </summary>
    /// <typeparam name="T">The type of transport layer connection analysis to retrieve. Must implement ITransportLayerConnectionAnalysis.</typeparam>
    /// <returns>An instance of the specified transport layer connection analysis type.</returns>
    /// <exception cref="Exception">Thrown if no transport layer connection analysis of the specified type is found.</exception>
    T GetRequiredTransportLayerConnectionAnalysis<T>() where T : ITransportLayerConnectionAnalysis
    {
        return GetTransportLayerConnectionAnalysis<T>() ?? throw new Exception($"No Transport Layer analysis found for the type {typeof(T).Name}");
    }

    /// <summary>
    /// Gets an analysis object for the specified application layer connection type, if available.
    /// </summary>
    /// <typeparam name="T">The type of application layer connection analysis to retrieve. Must implement
    /// IApplicationLayerConnectionAnalysis.</typeparam>
    /// <returns>An instance of the requested application layer connection analysis type if available; otherwise, null.</returns>
    T? GetApplicationLayerConnectionAnalysis<T>() where T : IApplicationLayerConnectionAnalysis;

    /// <summary>
    /// Retrieves a required application layer connection analysis of the specified type. Throws an exception if the
    /// analysis is not found.
    /// </summary>
    /// <typeparam name="T">The type of application layer connection analysis to retrieve. Must implement
    /// IApplicationLayerConnectionAnalysis.</typeparam>
    /// <returns>An instance of the requested application layer connection analysis type.</returns>
    /// <exception cref="Exception">Thrown if no application layer connection analysis is found for the specified type.</exception>
    T GetRequiredApplicationLayerConnectionAnalysis<T>() where T : IApplicationLayerConnectionAnalysis
    {
        return GetApplicationLayerConnectionAnalysis<T>() ?? throw new Exception($"No Application Layer analysis found for the type {typeof(T).Name}");
    }

    /// <summary>
    /// Enumerable with all packet analyses in this container.
    /// </summary>
    IEnumerable<IPacketAnalysis> PacketAnalyses { get; }

    /// <summary>
    /// Enumerable with all transport layer analyses in this container.
    /// </summary>
    IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses { get; }

    /// <summary>
    /// Enumerable with all application layer analyses in this container.
    /// </summary>
    IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses { get; }
}
