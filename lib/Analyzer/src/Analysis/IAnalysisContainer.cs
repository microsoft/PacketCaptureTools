using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis;

/// <summary>
/// Defines a container for accessing registered analysis.
/// </summary>
public interface IAnalysisContainer : IAnalysisProvider
{
    /// <summary>
    /// Adds a packet analysis instance.
    /// </summary>
    /// <typeparam name="T">The type of packet analysis to add. Must implement the IPacketAnalysis interface.</typeparam>
    /// <param name="analysis">The packet analysis instance to add. Cannot be null.</param>
    public void AddPacketAnalysis<T>(T analysis) where T : IPacketAnalysis;

    /// <summary>
    /// Adds a transport layer connection analysis.
    /// </summary>
    /// <typeparam name="T">The type of transport layer connection analysis to add. Must implement the ITransportLayerConnectionAnalysis
    /// interface.</typeparam>
    /// <param name="analysis">The transport layer connection analysis instance to add. Cannot be null.</param>
    public void AddTransportLayerConnectionAnalysis<T>(T analysis) where T : ITransportLayerConnectionAnalysis;

    /// <summary>
    /// Adds an application layer connection analysis.
    /// </summary>
    /// <typeparam name="T">The type of the analysis to add. Must implement the IApplicationLayerConnectionAnalysis interface.</typeparam>
    /// <param name="analysis">The analysis instance to add. Cannot be null.</param>
    public void AddApplicationLayerConnectionAnalysis<T>(T analysis) where T : IApplicationLayerConnectionAnalysis;
}
