// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport.Tcp;
using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp;

/// <summary>
/// TCP connection analysis.
/// </summary>
public abstract class TcpConnectionAnalysis : ITransportLayerConnectionAnalysis
{
    /// <inheritdoc />
    public void Process(CapturedPacket packet, TransportConnectionSnapshot transportConnectionSnapshot)
    {
        if (transportConnectionSnapshot is TcpConnectionSnapshot tcpConnectionSnapshot)
        {
            Process(packet, tcpConnectionSnapshot);
        }
    }

    /// <summary>
    /// Processes the TCP/IP packet headers for analysis.
    /// </summary>
    /// <param name="packet">Captured packet containing data and time of capture.</param>
    /// <param name="tcpConnectionSnapshot">The TCP connection snapshot.</param>
    public abstract void Process(CapturedPacket packet, TcpConnectionSnapshot tcpConnectionSnapshot);
}
