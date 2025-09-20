// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Extensions;

public class TimeSpanExtensionsTests
{
    [Fact]
    public void ToReadableFormat_TimeSpanNullableIsNull_ReturnNull()
    {
        // Arrange
        TimeSpan? input = null;

        // Act
        var result = input.ToReadableFormat();

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToReadableFormat_TimeSpanNullableIsNotNull_ReturnReadableFormat()
    {
        // Arrange
        TimeSpan? input = new TimeSpan(
            days: 0,
            hours: 0,
            minutes: 0,
            seconds: 45,
            milliseconds: 123);

        var expectedResult = "45.1 s";

        // Act
        var result = input.ToReadableFormat();

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    //          d  h  m  s  ms
    [InlineData(0, 0, 0, 0, 0, "0 ms")]
    [InlineData(0, 0, 0, 0, 1, "1 ms")]
    [InlineData(0, 0, 0, 0, 12, "12 ms")]
    [InlineData(0, 0, 0, 0, 123, "123 ms")]
    [InlineData(0, 0, 0, 5, 3, "5 s")]
    [InlineData(0, 0, 0, 5, 123, "5.12 s")]
    [InlineData(0, 0, 0, 45, 123, "45.1 s")]
    [InlineData(0, 0, 2, 0, 123, "2 m")]
    [InlineData(0, 0, 2, 45, 123, "2m 45s")]
    [InlineData(0, 0, 12, 45, 123, "12m 45s")]
    [InlineData(0, 6, 0, 45, 123, "6 h")]
    [InlineData(0, 6, 12, 45, 123, "6h 12m")]
    [InlineData(0, 16, 12, 45, 123, "16h 12m")]
    [InlineData(3, 0, 12, 45, 123, "3 d")]
    [InlineData(3, 16, 12, 45, 123, "3d 16h")]
    [InlineData(63, 16, 12, 45, 123, "63d 16h")]
    [InlineData(163, 16, 12, 45, 123, "163 d")]
    public void ToReadableFormat_TimeSpan(int days, int hours, int minutes, int seconds, int milliseconds, string expectedResult)
    {
        // Arrange
        var input = new TimeSpan(days, hours, minutes, seconds, milliseconds);

        // Act
        var result = input.ToReadableFormat();

        // Assert
        result.Should().Be(expectedResult);
    }
}