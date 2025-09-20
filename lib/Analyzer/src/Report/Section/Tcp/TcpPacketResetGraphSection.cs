// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using System;
using System.Linq;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;

/// <summary>
/// Tcp Packet Reset Graph Section which graphs the Tcp resets over time.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TcpPacketResetGraphSection" /> class.
/// </remarks>
/// <param name="tcpPacketResetAnalysis">TCP packet reset analysis.</param>
/// <exception cref="ArgumentNullException">Thrown if <paramref name="tcpPacketResetAnalysis" /> is null.</exception>
public class TcpPacketResetGraphSection(TcpPacketResetAnalysis tcpPacketResetAnalysis) : DateTimeGraphSection
{
    private readonly TcpPacketResetAnalysis _tcpPacketResetAnalysis = tcpPacketResetAnalysis ?? throw new ArgumentNullException(nameof(tcpPacketResetAnalysis));

    public TcpPacketResetGraphSection(IAnalysisProvider analysisProvider)
        : this(analysisProvider.GetRequiredPacketAnalysis<TcpPacketResetAnalysis>())
    {
    }

    /// <inheritdoc />
    protected override string SectionTitle => "TCP Resets";

    /// <inheritdoc />
    protected override string NoDataMessage => "TCP reset analysis analysis graph cannot be created - captured packets didn't contain any TCP resets.";

    /// <inheritdoc />
    protected override string GraphHeaderTitle => "TCP Total Reset Analysis";

    /// <inheritdoc />
    protected override string GraphHeaderDescription => "Graph showing TCP connection resets over the period of the packet capture operation.";

    /// <inheritdoc />
    protected override string GraphXAxisLabel => "TIME PERIOD OF DAY (HH:MM:SS)";

    /// <inheritdoc />
    protected override string GraphYAxisLabel => "TCP RESETS";

    /// <inheritdoc />
    protected override string GraphXAxisDateTimeFormat => "HH:mm:ss";

    /// <inheritdoc />
    protected override long[] GetXAxisData()
    {
        return [.. _tcpPacketResetAnalysis.CountBySecond.Keys.Select(x => x.Ticks)];
    }

    /// <inheritdoc />
    protected override long[] GetYAxisData()
    {
        return [.. _tcpPacketResetAnalysis.CountBySecond.Values.Select(x => (long)x)];
    }
}
