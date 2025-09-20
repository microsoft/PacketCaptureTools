// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using System.Linq;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Analysis.Metrics;

public class TimestampMetricsTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(101)]
    public void GetTimestampForPercentile_InvalidPercentile_ReturnsNull(int percentile)
    {
        // Arrange
        var metrics = new TimestampMetrics(new[] { TimeSpan.FromSeconds(1) });

        // Act
        var timestampForPercentile = metrics.GetTimestampForPercentile(percentile);

        // Assert
        timestampForPercentile.Should().BeNull();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(99)]
    [InlineData(100)]
    public void GetTimestampForPercentile_NoMetricsForValidPercentile_ReturnsNull(int percentile)
    {
        // Arrange
        var metrics = new TimestampMetrics();

        // Act
        var timestampForPercentile = metrics.GetTimestampForPercentile(percentile);

        // Assert
        timestampForPercentile.Should().BeNull();
    }

    [Fact]
    public void GetTimestampForPercentile_ValidInput_AllMetricsShouldCalculateCorrectValues()
    {
        // Arrange
        var minValue = TimeSpan.Zero;
        var secondSmallestValue = TimeSpan.FromMilliseconds(200);
        var medianValue = TimeSpan.FromSeconds(2);
        var secondBiggestValue = TimeSpan.FromSeconds(15);
        var maxValue = TimeSpan.FromMinutes(2);

        var values = new[]
        {
            minValue,
            secondSmallestValue,
            medianValue,
            secondBiggestValue,
            maxValue,
        };

        var metrics = new TimestampMetrics(values);

        var expectedTotal = (decimal)values.Sum(x => x.TotalMilliseconds);
        var expectedAverage = values.Average(x => x.TotalMilliseconds);

        var expectedTimestampForPercentile99 = maxValue.ToReadableFormat();
        var expectedTimestampForPercentile75 = secondBiggestValue.ToReadableFormat();
        var expectedTimestampForPercentile50 = medianValue.ToReadableFormat();
        var expectedTimestampForPercentile25 = secondSmallestValue.ToReadableFormat();
        var expectedTimestampForPercentile00 = minValue.ToReadableFormat();

        // Act
        var timestampForPercentile99 = metrics.GetTimestampForPercentile(99);
        var timestampForPercentile75 = metrics.GetTimestampForPercentile(75);
        var timestampForPercentile50 = metrics.GetTimestampForPercentile(50);
        var timestampForPercentile25 = metrics.GetTimestampForPercentile(25);
        var timestampForPercentile00 = metrics.GetTimestampForPercentile(0);

        // Assert
        timestampForPercentile99.Should().Be(expectedTimestampForPercentile99);
        timestampForPercentile75.Should().Be(expectedTimestampForPercentile75);
        timestampForPercentile50.Should().Be(expectedTimestampForPercentile50);
        timestampForPercentile25.Should().Be(expectedTimestampForPercentile25);
        timestampForPercentile00.Should().Be(expectedTimestampForPercentile00);

        metrics.IsEmpty.Should().Be(false);
        metrics.Count.Should().Be((ulong)values.Length);
        metrics.Maximum.Should().Be(maxValue);
        metrics.Minimum.Should().Be(minValue);
        metrics.Total.Should().Be(expectedTotal);
        metrics.Average.Should().Be(TimeSpan.FromMilliseconds(expectedAverage));
        metrics.Median.Should().Be(medianValue);
    }
}