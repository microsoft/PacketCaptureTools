// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Counter;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Retransmission;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport.Tcp.Timings;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tcp;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;

namespace Microsoft.PacketCapture.Analyzer.Test.Common;

internal static class SectionFixtureFactory
{
    internal static GlobalPacketCountersTableSection GetGlobalPacketCountersTableSectionFixture(
        PacketCounterAnalysis? packetCounterAnalysis = null,
        TcpConnectionRetransmissionAnalysis? tcpConnectionRetransmissionAnalysis = null,
        TcpConnectionCounterAnalysis? tcpConnectionCounterAnalysis = null,
        TcpPacketResetAnalysis? tcpPacketResetAnalysis = null,
        TcpPercentageOfDataControlAnalysis? tcpPercentageOfDataControlAnalysis = null)
    {
        return new GlobalPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis ?? AnalysisFixtureFactory.GetPacketCounterAnalysis(),
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis ?? AnalysisFixtureFactory.GetTcpConnectionRetransmissionAnalysis(),
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis ?? AnalysisFixtureFactory.GetTcpConnectionCounterAnalysis(),
            tcpPacketResetAnalysis: tcpPacketResetAnalysis ?? AnalysisFixtureFactory.GetTcpPacketResetAnalysis(),
            tcpPercentageOfDataControlAnalysis: tcpPercentageOfDataControlAnalysis ?? AnalysisFixtureFactory.GetTcpPercentageOfDataControlAnalysis());
    }

    internal static PerIpPacketCountersTableSection GetPerIpPacketCountersTableSection(
        PacketCounterAnalysis? packetCounterAnalysis = null,
        TcpConnectionRetransmissionAnalysis? tcpConnectionRetransmissionAnalysis = null,
        TcpConnectionCounterAnalysis? tcpConnectionCounterAnalysis = null,
        TcpPacketResetAnalysis? tcpPacketResetAnalysis = null)
    {
        return new PerIpPacketCountersTableSection(
            packetCounterAnalysis: packetCounterAnalysis ?? AnalysisFixtureFactory.GetPacketCounterAnalysis(),
            tcpConnectionRetransmissionAnalysis: tcpConnectionRetransmissionAnalysis ?? AnalysisFixtureFactory.GetTcpConnectionRetransmissionAnalysis(),
            tcpConnectionCounterAnalysis: tcpConnectionCounterAnalysis ?? AnalysisFixtureFactory.GetTcpConnectionCounterAnalysis(),
            tcpPacketResetAnalysis: tcpPacketResetAnalysis ?? AnalysisFixtureFactory.GetTcpPacketResetAnalysis());
    }

    internal static PacketCountersPerProtocolCompositeSection GetPacketCountersPerProtocolCompositeSection(PacketCounterAnalysis? packetCounterAnalysis = null)
    {
        packetCounterAnalysis ??= AnalysisFixtureFactory.GetPacketCounterAnalysis();

        return new PacketCountersPerProtocolCompositeSection(
            GetNetworkLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis),
            GetTransportLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis));
    }

    internal static NetworkLayerPacketCountersPerProtocolTableSection GetNetworkLayerPacketCountersPerProtocolTableSection(PacketCounterAnalysis? packetCounterAnalysis = null)
    {
        return new NetworkLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis ?? AnalysisFixtureFactory.GetPacketCounterAnalysis());
    }

    internal static TransportLayerPacketCountersPerProtocolTableSection GetTransportLayerPacketCountersPerProtocolTableSection(PacketCounterAnalysis? packetCounterAnalysis = null)
    {
        return new TransportLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis ?? AnalysisFixtureFactory.GetPacketCounterAnalysis());
    }

    internal static TcpTrafficTimingsTableSection GetTrafficTimingsTableSection(TcpConnectionTimingsAnalysis? tcpConnectionTimingsAnalysis = null)
    {
        return new TcpTrafficTimingsTableSection(tcpConnectionTimingsAnalysis ?? AnalysisFixtureFactory.GetTcpConnectionTimingsAnalysis());
    }

    public static ThroughputPacketTableSection GetThroughputPacketTableSection(ThroughputAnalysis? throughputAnalysis = null)
    {
        return new ThroughputPacketTableSection(throughputAnalysis ?? AnalysisFixtureFactory.GetThroughputAnalysis());
    }

    public static TdsFailedLoginConnectionTableSection GetTdsFailedLoginConnectionTableSection(TdsLoginConnectionAnalysis? tdsLoginConnectionAnalysis = null)
    {
        return new TdsFailedLoginConnectionTableSection(tdsLoginConnectionAnalysis ?? AnalysisFixtureFactory.GetTdsLoginConnectionAnalysis());
    }

    public static TdsLoginConnectionAnalysesTableSection GetTdsLoginConnectionAnalysesTableSection(TdsLoginConnectionAnalysis? tdsLoginConnectionAnalysis = null)
    {
        return new TdsLoginConnectionAnalysesTableSection(tdsLoginConnectionAnalysis ?? AnalysisFixtureFactory.GetTdsLoginConnectionAnalysis());
    }

    public static TdsFailedConnectionLatencyTableSection GetTdsFailedConnectionLatencyTableSection(TdsConnectionLatencyAnalysis? tdsConnectionLatencyAnalysis = null)
    {
        return new TdsFailedConnectionLatencyTableSection(tdsConnectionLatencyAnalysis ?? AnalysisFixtureFactory.GetTdsConnectionLatencyAnalysis());
    }

    public static TdsAverageLoginLatencyGraphSection GetTdsAverageLoginLatencyGraphSection(TdsConnectionLatencyAnalysis? tdsConnectionLatencyAnalysis = null)
    {
        return new TdsAverageLoginLatencyGraphSection(tdsConnectionLatencyAnalysis ?? AnalysisFixtureFactory.GetTdsConnectionLatencyAnalysis());
    }

    public static TdsFailedLoginGraphSection GetTdsFailedLoginGraphSection(TdsLoginConnectionAnalysis? tdsLoginConnectionAnalysis = null)
    {
        return new TdsFailedLoginGraphSection(tdsLoginConnectionAnalysis ?? AnalysisFixtureFactory.GetTdsLoginConnectionAnalysis());
    }
}