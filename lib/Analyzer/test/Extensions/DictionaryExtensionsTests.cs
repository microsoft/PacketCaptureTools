// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Metrics;
using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Extensions;

public class DictionaryExtensionsTests
{
    [Fact]
    public void InsertIntoMetrics_TimestampMetricsDoesNotExist_CreateNewTimestampMetrics()
    {
        // Arrange
        var sut = new Dictionary<int, TimestampMetrics>();

        var key = 1;
        var value = TimeSpan.FromMinutes(1);

        // Act
        sut.InsertIntoMetrics(key, value);

        // Assert
        sut[key].Count.Should().Be(1);
        sut[key].Minimum.Should().Be(value);
        sut[key].Maximum.Should().Be(value);
        sut[key].Average.Should().Be(value);
    }

    [Fact]
    public void InsertIntoMetrics_TimestampMetricsAlreadyExists_InsertElementIntoTimestampMetrics()
    {
        // Arrange
        var sut = new Dictionary<int, TimestampMetrics>();

        var key = 1;
        var value = TimeSpan.FromMinutes(1);

        var timestampMetrics = new TimestampMetrics();
        timestampMetrics.Insert(value);

        sut[key] = timestampMetrics;

        var newValue = TimeSpan.FromMinutes(2);

        var expectedAverage = TimeSpan.FromTicks((newValue.Ticks + value.Ticks) / 2);

        // Act
        sut.InsertIntoMetrics(key, newValue);

        // Assert
        sut[key].Count.Should().Be(2);
        sut[key].Minimum.Should().Be(value);
        sut[key].Maximum.Should().Be(newValue);
        sut[key].Average.Should().Be(expectedAverage);
    }
}