// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using Microsoft.PacketCapture.Analyzer.Test.Common;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class PacketCountersPerProtocolCompositeSectionTests
{
    [Fact]
    public void Constructor_ReturnsCorrectSubsections()
    {
        // Arrange
        var networkLayerPacketCountersPerProtocolTableSection = new NetworkLayerPacketCountersPerProtocolTableSection(AnalysisFixtureFactory.GetPacketCounterAnalysis());
        var transportLayerPacketCountersPerProtocolTableSection = new TransportLayerPacketCountersPerProtocolTableSection(AnalysisFixtureFactory.GetPacketCounterAnalysis());

        // Act
        var sut = new PacketCountersPerProtocolCompositeSection(
            networkLayerPacketCountersPerProtocolTableSection, 
            transportLayerPacketCountersPerProtocolTableSection);

        // Assert
        sut.Subsections.Count().Should().Be(2);
        sut.Subsections.Should().Contain(networkLayerPacketCountersPerProtocolTableSection);
        sut.Subsections.Should().Contain(transportLayerPacketCountersPerProtocolTableSection);
    }
}