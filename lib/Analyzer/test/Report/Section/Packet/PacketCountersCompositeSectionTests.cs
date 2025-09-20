// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class PacketCountersCompositeSectionTests
{
    [Fact]
    public void Constructor_ReturnsCorrectSubsections()
    {
        // Arrange
        var packetCounterAnalysis = AnalysisFixtureFactory.GetPacketCounterAnalysis();
        var tcpConnectionRetransmissionAnalysis = AnalysisFixtureFactory.GetTcpConnectionRetransmissionAnalysis();
        var tcpConnectionCounterAnalysis = AnalysisFixtureFactory.GetTcpConnectionCounterAnalysis();
        var tcpPacketResetAnalysis = AnalysisFixtureFactory.GetTcpPacketResetAnalysis();
        var tcpPercentageOfDataControlAnalysis = AnalysisFixtureFactory.GetTcpPercentageOfDataControlAnalysis();
        var throughputAnalysis = AnalysisFixtureFactory.GetThroughputAnalysis();

        var globalPacketCountersTableSection = new GlobalPacketCountersTableSection(
            packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis,
            tcpPercentageOfDataControlAnalysis);
        var perIpPacketCountersTableSection = new PerIpPacketCountersTableSection(
            packetCounterAnalysis,
            tcpConnectionRetransmissionAnalysis,
            tcpConnectionCounterAnalysis,
            tcpPacketResetAnalysis);
        var packetCountersPerProtocolCompositeSection = new PacketCountersPerProtocolCompositeSection(
            new NetworkLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis),
            new TransportLayerPacketCountersPerProtocolTableSection(packetCounterAnalysis));
        var throughputPacketTableSection = new ThroughputPacketTableSection(throughputAnalysis);

        // Act
        var sut = new PacketCountersCompositeSection(
            globalPacketCountersTableSection,
            packetCountersPerProtocolCompositeSection,
            throughputPacketTableSection,
            perIpPacketCountersTableSection);

        // Assert
        sut.Subsections.Count().Should().Be(4);
        sut.Subsections.Should().Contain(globalPacketCountersTableSection);
        sut.Subsections.Should().Contain(throughputPacketTableSection);
        sut.Subsections.Should().Contain(packetCountersPerProtocolCompositeSection);
        sut.Subsections.Should().Contain(perIpPacketCountersTableSection);
    }
}