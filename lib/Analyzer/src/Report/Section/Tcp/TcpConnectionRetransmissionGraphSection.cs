// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using System;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;

/// <summary>
/// Tcp Packet Reset Graph Section which graphs the Tcp resets over time.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TcpConnectionRetransmissionGraphSection" /> class.
/// </remarks>
/// <param name="tcpConnectionRetransmissionAnalysis">TCP connection retransmission analysis.</param>
/// <exception cref="ArgumentNullException">Thrown if <paramref name="tcpConnectionRetransmissionAnalysis" /> is null.</exception>
public class TcpConnectionRetransmissionGraphSection(TcpConnectionRetransmissionAnalysis tcpConnectionRetransmissionAnalysis) : DateTimeGraphSection
{
    private readonly TcpConnectionRetransmissionAnalysis _tcpConnectionRetransmissionAnalysis = tcpConnectionRetransmissionAnalysis ?? throw new ArgumentNullException(nameof(tcpConnectionRetransmissionAnalysis));

    public TcpConnectionRetransmissionGraphSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredTransportLayerConnectionAnalysis<TcpConnectionRetransmissionAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string SectionTitle => "TCP Retransmits";

    /// <inheritdoc />
    protected override string NoDataMessage => "TCP retransmission analysis graph cannot be created - captured packets didn't contain any outgoing TCP retransmits.";

    /// <inheritdoc />
    protected override string GraphHeaderTitle => "TCP Total Outgoing Retransmits Analysis";

    /// <inheritdoc />
    protected override string GraphHeaderDescription => "Graph showing TCP retransmits, originating from the capture host, over the period of the packet capture operation.";

    /// <inheritdoc />
    protected override string GraphXAxisLabel => "TIME PERIOD OF DAY (HH:MM:SS)";

    /// <inheritdoc />
    protected override string GraphYAxisLabel => "TCP RETRANSMITS";

    /// <inheritdoc />
    protected override string GraphXAxisDateTimeFormat => "HH:mm:ss";

    /// <inheritdoc />
    protected override long[] GetXAxisData()
    {
        return [.. _tcpConnectionRetransmissionAnalysis.RetransmissionsByTime.Keys.Select(x => x.Ticks)];
    }

    /// <inheritdoc />
    protected override long[] GetYAxisData()
    {
        return [.. _tcpConnectionRetransmissionAnalysis.RetransmissionsByTime.Values.Select(x => (long)x)];
    }
}
