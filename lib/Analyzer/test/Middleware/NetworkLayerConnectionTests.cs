// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware;
using System;
using System.Collections.Generic;
using Xunit;
using static System.Net.IPAddress;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware;

public class NetworkLayerConnectionTests
{
    private const string FirstIpAddress = "192.168.0.1";
    private const string SecondIpAddress = "192.168.0.2";
    private const string ThirdIpAddress = "192.168.0.3";

    private readonly NetworkLayerConnection _sut;

    public NetworkLayerConnectionTests()
    {
        _sut = new NetworkLayerConnection(
            sourceIpAddress: Parse(FirstIpAddress),
            destinationIpAddress: Parse(SecondIpAddress));
    }

    [Fact]
    public void ClassConstructor_SourceIpAddressIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "sourceIpAddress";

        // Act
        Func<NetworkLayerConnection> function = () => new NetworkLayerConnection(
            sourceIpAddress: null!,
            destinationIpAddress: Parse(SecondIpAddress));

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Fact]
    public void ClassConstructor_DestinationIpAddressIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "destinationIpAddress";

        // Act
        Func<NetworkLayerConnection> function = () => new NetworkLayerConnection(
            sourceIpAddress: Parse(FirstIpAddress),
            destinationIpAddress: null!);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Theory]
    [InlineData(FirstIpAddress, SecondIpAddress, true)]
    [InlineData(SecondIpAddress, FirstIpAddress, true)]
    [InlineData(FirstIpAddress, ThirdIpAddress, false)]
    public void EqualsOverride(string sourceIpAddress, string destinationIpAddress, bool expectedResult)
    {
        // Arrange
        var expectedConnection = new NetworkLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress));

        // Act
        var result = _sut.Equals(expectedConnection);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData(FirstIpAddress, SecondIpAddress, true, true)]
    [InlineData(SecondIpAddress, FirstIpAddress, true, false)]
    public void IsSameConnection(string sourceIpAddress, string destinationIpAddress, bool expectedResult, bool expectedHasSameDirection)
    {
        // Arrange
        var expectedConnection = new NetworkLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress));

        // Act
        var result = _sut.IsSameConnection(expectedConnection, out var hasHasSameDirection);

        // Assert
        result.Should().Be(expectedResult);
        hasHasSameDirection.Should().Be(expectedHasSameDirection);
    }

    [Theory]
    [InlineData(FirstIpAddress, SecondIpAddress, true)]
    [InlineData(SecondIpAddress, FirstIpAddress, true)]
    [InlineData(FirstIpAddress, ThirdIpAddress, false)]
    [InlineData(ThirdIpAddress, FirstIpAddress, false)]
    public void CollectionContains(string sourceIpAddress, string destinationIpAddress, bool expectedResult)
    {
        // Arrange
        var hashSet = new HashSet<NetworkLayerConnection>();

        var expectedConnection = new NetworkLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress));

        hashSet.Add(expectedConnection);

        // Act
        var result = hashSet.Contains(_sut);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void GetHashCode_ReverseDirectionConnectionHashCodeShouldBeTheSame()
    {
        // Arrange
        var reverseDirectionConnection = new NetworkLayerConnection(
            sourceIpAddress: Parse(SecondIpAddress),
            destinationIpAddress: Parse(FirstIpAddress));

        // Act
        var hashCode = _sut.GetHashCode();
        var reverseDirectionHashCode = reverseDirectionConnection.GetHashCode();

        // Assert
        hashCode.Should().Be(reverseDirectionHashCode);
    }
}