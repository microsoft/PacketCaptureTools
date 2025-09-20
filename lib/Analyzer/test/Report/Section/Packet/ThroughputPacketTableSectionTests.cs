// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Packet;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Packet;

public class ThroughputPacketTableSectionTests
{
    private const string HeaderTitle = "Throughput";
    private const string HeaderDescription = "The average, minimum and maximum number of packets and data transferred per second.";
    private const string NoDataMessage = "Throughput table cannot be created - not enough packets to calculate throughput were captured.";
    private readonly TextRenderer _textRenderer;

    public ThroughputPacketTableSectionTests()
    {
        _textRenderer = new TextRenderer();
    }

    [Fact]
    public void Constructor_PacketCounterAnalysisIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        var argumentName = "packetCounterAnalysis";

        // Act
        Func<NetworkLayerPacketCountersPerProtocolTableSection> function =
            () => new NetworkLayerPacketCountersPerProtocolTableSection((PacketCounterAnalysis)null!);

        // Assert
        function.Should().Throw<ArgumentNullException>(argumentName);
    }

    [Fact]
    public void Render_TextRendererNoData_RendersNoDataMessage()
    {
        // Arrange
        var throughputAnalysis = new ThroughputAnalysis();

        var sut = new ThroughputPacketTableSection(throughputAnalysis);

        var expectedResult =
            $@"{NoDataMessage}

";

        // Act
        sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void Render_TextRenderer_RendersPerIpPacketCountersTableSection()
    {
        // Arrange
        var sut = GetThroughputPacketTableSection(
            maxNumberOfPackets: 1000,
            minNumberOfPackets: 20,
            averageNumberOfPackets: 50,
            maxSpeedOfDataTransfer: 1000,
            minSpeedOfDataTransfer: 10,
            averageSpeedOfDataTransfer: 500);

        var expectedResult =
            $@"[{HeaderTitle}]
{HeaderDescription}

+-------------------+---------+--------+----------+
| Value             | Average | Min    | Max      |
+-------------------+---------+--------+----------+
| Number of Packets | 50 /s   | 20 /s  | 1000 /s  |
| Speed             | 500 B/s | 10 B/s | 1000 B/s |
+-------------------+---------+--------+----------+

";

        // Act
        sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }

    private static ThroughputPacketTableSection GetThroughputPacketTableSection(
        long maxNumberOfPackets,
        long minNumberOfPackets,
        long averageNumberOfPackets,
        long maxSpeedOfDataTransfer,
        long minSpeedOfDataTransfer,
        long averageSpeedOfDataTransfer)
    {
        var throughputAnalysis = new ThroughputAnalysis(
            fullTimeSlotExists: true,
            totalNumberOfPackets: averageNumberOfPackets,
            totalAmountOfBytesPassed: averageSpeedOfDataTransfer,
            maxNumberOfPackets: maxNumberOfPackets,
            minNumberOfPackets: minNumberOfPackets,
            maxSpeedOfDataTransfer: maxSpeedOfDataTransfer,
            minSpeedOfDataTransfer: minSpeedOfDataTransfer);

        return new ThroughputPacketTableSection(throughputAnalysis);
    }
}