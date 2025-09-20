// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Middleware.Application;
using Microsoft.PacketCapture.Analyzer.Middleware.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Packet;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;

/// <summary>
/// TDS protocol connection analysis.
/// </summary>
public abstract class TdsConnectionAnalysis : IApplicationLayerConnectionAnalysis
{
    /// <inheritdoc />
    public void Process(CapturedPacket packet, ApplicationConnectionSnapshot applicationConnectionSnapshot)
    {
        if (applicationConnectionSnapshot is TdsConnectionSnapshot tdsConnectionSnapshot)
        {
            Process(packet, tdsConnectionSnapshot);
        }
    }

    /// <summary>
    /// Process TDS connection snapshot through analysis.
    /// </summary>
    /// <param name="packet">The captured packet.</param>
    /// <param name="tdsConnectionSnapshot">The TDS connection snapshot.</param>
    public abstract void Process(CapturedPacket packet, TdsConnectionSnapshot tdsConnectionSnapshot);
}
