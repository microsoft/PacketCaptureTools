// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section;

public class GraphSectionTests
{
    [Fact]
    public void ShouldBeRendered_XAxisDataIsNull_ReturnsFalse()
    {
        // Arrange
        var yAxisData = new long[] { 1 };

        // Act
        var sut = new GraphSectionFake(null!, yAxisData);

        // Assert
        sut.ShouldBeRendered.Should().BeFalse();
    }

    [Fact]
    public void ShouldBeRendered_YAxisDataIsNull_ReturnsFalse()
    {
        // Arrange
        var xAxisData = new long[] { 1 };

        // Act
        var sut = new GraphSectionFake(xAxisData, null!);

        // Assert
        sut.ShouldBeRendered.Should().BeFalse();
    }


    [Fact]
    public void ShouldBeRendered_XAxisDataIsNullYAxisDataIsNull_ReturnsFalse()
    {
        // Arrange
        // Act
        var sut = new GraphSectionFake(null, null);

        // Assert
        sut.ShouldBeRendered.Should().BeFalse();
    }

    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(0, 1, false)]
    [InlineData(1, 0, false)]
    [InlineData(1, 1, true)]
    public void ShouldBeRendered_WithDataLength_ReturnsExpectedResult(int xAxisDataLength, int yAxisDataLength, bool expectedResult)
    {
        // Arrange
        var xAxisData = new long[xAxisDataLength];
        var yAxisData = new long[yAxisDataLength];

        // Act
        var sut = new GraphSectionFake(xAxisData, yAxisData);

        // Assert
        sut.ShouldBeRendered.Should().Be(expectedResult);
    }

    private class GraphSectionFake(long[]? xAxisData, long[]? yAxisData) : GraphSection
    {
        private readonly long[]? _xAxisData = xAxisData;
        private readonly long[]? _yAxisData = yAxisData;

        protected override string NoDataMessage => "NoDataMessage";

        protected override string GraphHeaderTitle => "GraphHeaderTitle";

        protected override string GraphHeaderDescription => "GraphHeaderDescription";

        protected override string GraphXAxisLabel => "GraphXAxisLabel";

        protected override string GraphYAxisLabel => "GraphYAxisLabel";

        protected override Func<long, string> GraphXAxisValueFormatter => x => x.ToString();

        protected override Func<long, string> GraphYAxisValueFormatter => y => y.ToString();

        protected override long[]? GetXAxisData()
        {
            return _xAxisData;
        }

        protected override long[]? GetYAxisData()
        {
            return _yAxisData;
        }
    }
}