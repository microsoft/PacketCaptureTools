// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Extensions;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Extensions;

public class EnumTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    public void ToDictionary(int defaultValue)
    {
        // Arrange
        // Act
        var dictionary = Enum<TestEnum>.AsDictionary(defaultValue);

        // Assert
        dictionary.Count.Should().Be(3);
        dictionary.ContainsKey(TestEnum.Val1).Should().BeTrue();
        dictionary.ContainsKey(TestEnum.Val2).Should().BeTrue();
        dictionary.ContainsKey(TestEnum.Val3).Should().BeTrue();
        dictionary[TestEnum.Val1].Should().Be(defaultValue);
        dictionary[TestEnum.Val2].Should().Be(defaultValue);
        dictionary[TestEnum.Val3].Should().Be(defaultValue);
    }

    private enum TestEnum
    {
        Val1,
        Val2,
        Val3,
    }
}