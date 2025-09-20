// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Application.Tds.Latency;
using Microsoft.PacketCapture.Analyzer.Report.Section.Tds;
using Moq;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section.Tds;

public class TdsAnalysisCompositeSectionTests
{
    [Fact]
    public void Constructor_ReturnsCorrectSubsections()
    {
        // Arrange
        var tdsFailedLoginConnectionTableSection = new Mock<TdsFailedLoginConnectionTableSection>(new Mock<TdsLoginConnectionAnalysis>().Object).Object;
        var tdsLoginConnectionAnalysesTableSection = new Mock<TdsLoginConnectionAnalysesTableSection>(new Mock<TdsLoginConnectionAnalysis>().Object).Object;
        var tdsFailedConnectionLatencyTableSection = new Mock<TdsFailedConnectionLatencyTableSection>(new Mock<TdsConnectionLatencyAnalysis>().Object).Object;
        var tdsAverageLoginLatencyGraphSection = new Mock<TdsAverageLoginLatencyGraphSection>(new Mock<TdsConnectionLatencyAnalysis>().Object).Object;
        var tdsFailedLoginGraphSection = new Mock<TdsFailedLoginGraphSection>(new Mock<TdsLoginConnectionAnalysis>().Object).Object;

        // Act
        var sut = new TdsAnalysisCompositeSection(
            tdsFailedLoginConnectionTableSection, 
            tdsLoginConnectionAnalysesTableSection,
            tdsFailedConnectionLatencyTableSection,
            tdsAverageLoginLatencyGraphSection, 
            tdsFailedLoginGraphSection);

        // Assert
        sut.Subsections.Count().Should().Be(5);
        sut.Subsections.Should().Contain(tdsFailedLoginConnectionTableSection);
        sut.Subsections.Should().Contain(tdsLoginConnectionAnalysesTableSection);
        sut.Subsections.Should().Contain(tdsFailedConnectionLatencyTableSection);
        sut.Subsections.Should().Contain(tdsAverageLoginLatencyGraphSection);
        sut.Subsections.Should().Contain(tdsFailedLoginGraphSection);
    }
}