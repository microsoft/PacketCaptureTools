using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using System;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Analysis;

/// <summary>
/// Provides a container for registering and retrieving analysis.
/// </summary>
public class AnalysisContainer : IAnalysisContainer
{
    private readonly Dictionary<Type, IPacketAnalysis> _packetAnalyses = [];
    private readonly Dictionary<Type, ITransportLayerConnectionAnalysis> _transportLayerAnalyses = [];
    private readonly Dictionary<Type, IApplicationLayerConnectionAnalysis> _applicationLayerAnalyses = [];

    /// <inheritdoc />
    public void AddPacketAnalysis<T>(T analysis) where T : IPacketAnalysis
    {
        _packetAnalyses.Add(typeof(T), analysis);
    }

    /// <inheritdoc />
    public void AddTransportLayerConnectionAnalysis<T>(T analysis) where T : ITransportLayerConnectionAnalysis
    {
        _transportLayerAnalyses.Add(typeof(T), analysis);
    }

    /// <inheritdoc />
    public void AddApplicationLayerConnectionAnalysis<T>(T analysis) where T : IApplicationLayerConnectionAnalysis
    {
        _applicationLayerAnalyses.Add(typeof(T), analysis);
    }

    /// <inheritdoc />
    public IEnumerable<IPacketAnalysis> PacketAnalyses => _packetAnalyses.Values;

    /// <inheritdoc />
    public IEnumerable<ITransportLayerConnectionAnalysis> TransportLayerAnalyses => _transportLayerAnalyses.Values;

    /// <inheritdoc />
    public IEnumerable<IApplicationLayerConnectionAnalysis> ApplicationLayerAnalyses => _applicationLayerAnalyses.Values;

    /// <inheritdoc />
    public T? GetApplicationLayerConnectionAnalysis<T>() where T : IApplicationLayerConnectionAnalysis
    {
        _applicationLayerAnalyses.TryGetValue(typeof(T), out var analysis);
        return (T?)analysis;
    }

    /// <inheritdoc />
    public T? GetPacketAnalysis<T>() where T : IPacketAnalysis
    {
        _packetAnalyses.TryGetValue(typeof(T), out var analysis);
        return (T?)analysis;
    }

    /// <inheritdoc />
    public T? GetTransportLayerConnectionAnalysis<T>() where T : ITransportLayerConnectionAnalysis
    {
        _transportLayerAnalyses.TryGetValue(typeof(T), out var analysis);
        return (T?)analysis;
    }
}
