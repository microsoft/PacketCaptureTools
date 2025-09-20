// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Middleware;
using Microsoft.PacketCapture.Analyzer.Middleware.Transport;
using System;
using System.Collections.Generic;
using Xunit;
using static System.Net.IPAddress;

namespace Microsoft.PacketCapture.Analyzer.Test.Middleware.Transport;

public class TransportLayerConnectionTests
{
    private const string FirstIpAddress = "192.168.0.1";
    private const int FirstPort = 1;

    private const string SecondIpAddress = "192.168.0.2";
    private const int SecondPort = 2;

    private const string ThirdIpAddress = "192.168.0.3";
    private const int ThirdPort = 3;
    private readonly TransportLayerConnection _sut;

    public TransportLayerConnectionTests()
    {
        _sut = new TransportLayerConnection(
            sourceIpAddress: Parse(FirstIpAddress),
            destinationIpAddress: Parse(SecondIpAddress),
            sourcePort: FirstPort,
            destinationPort: SecondPort);
    }

    [Fact]
    public void ClassConstructor_SourceIpAddressIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        const string parameterName = "sourceIpAddress";

        // Act
        Func<TransportLayerConnection> function = () => new TransportLayerConnection(
            sourceIpAddress: null!,
            destinationIpAddress: Parse(SecondIpAddress),
            sourcePort: FirstPort,
            destinationPort: SecondPort);

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
        Func<TransportLayerConnection> function = () => new TransportLayerConnection(
            sourceIpAddress: Parse(FirstIpAddress),
            destinationIpAddress: null!,
            sourcePort: FirstPort,
            destinationPort: SecondPort);

        // Assert
        function.Should()
            .Throw<ArgumentNullException>()
            .And.ParamName.Should()
            .Be(parameterName);
    }

    [Theory]
    [InlineData(FirstIpAddress, FirstPort, SecondIpAddress, SecondPort, true)]
    [InlineData(SecondIpAddress, SecondPort, FirstIpAddress, FirstPort, true)]
    [InlineData(FirstIpAddress, SecondPort, SecondIpAddress, FirstPort, false)]
    [InlineData(FirstIpAddress, FirstPort, ThirdIpAddress, ThirdPort, false)]
    [InlineData(ThirdIpAddress, ThirdPort, FirstIpAddress, FirstPort, false)]
    public void EqualsOverride(string sourceIpAddress, int sourcePort, string destinationIpAddress, int destinationPort, bool expectedResult)
    {
        // Arrange
        var expectedConnection = new TransportLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress),
            sourcePort: sourcePort,
            destinationPort: destinationPort);

        // Act
        var result = _sut.Equals(expectedConnection);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData(FirstIpAddress, FirstPort, SecondIpAddress, SecondPort, true, true)]
    [InlineData(SecondIpAddress, SecondPort, FirstIpAddress, FirstPort, true, false)]
    [InlineData(FirstIpAddress, SecondPort, SecondIpAddress, FirstPort, false, false)]
    [InlineData(FirstIpAddress, FirstPort, ThirdIpAddress, ThirdPort, false, false)]
    [InlineData(ThirdIpAddress, ThirdPort, FirstIpAddress, FirstPort, false, false)]
    public void IsSameConnection(string sourceIpAddress, int sourcePort, string destinationIpAddress, int destinationPort, bool expectedResult, bool expectedHasSameDirection)
    {
        // Arrange
        var expectedConnection = new TransportLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress),
            sourcePort: sourcePort,
            destinationPort: destinationPort);

        // Act
        var result = _sut.IsSameConnection(expectedConnection, out var hasHasSameDirection);

        // Assert
        result.Should().Be(expectedResult);
        hasHasSameDirection.Should().Be(expectedHasSameDirection);
    }

    [Theory]
    [InlineData(FirstIpAddress, SecondIpAddress, true, true)]
    [InlineData(SecondIpAddress, FirstIpAddress, true, false)]
    [InlineData(FirstIpAddress, ThirdIpAddress, false, false)]
    [InlineData(ThirdIpAddress, FirstIpAddress, false, false)]
    public void IsSameConnection_NetworkLayerConnection(string sourceIpAddress, string destinationIpAddress, bool expectedResult, bool expectedHasSameDirection)
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
    [InlineData(FirstIpAddress, FirstPort, SecondIpAddress, SecondPort, true)]
    [InlineData(SecondIpAddress, SecondPort, FirstIpAddress, FirstPort, true)]
    [InlineData(FirstIpAddress, SecondPort, SecondIpAddress, FirstPort, false)]
    [InlineData(FirstIpAddress, FirstPort, ThirdIpAddress, ThirdPort, false)]
    [InlineData(ThirdIpAddress, ThirdPort, FirstIpAddress, FirstPort, false)]
    public void CollectionContains(string sourceIpAddress, int sourcePort, string destinationIpAddress, int destinationPort, bool expectedResult)
    {
        // Arrange
        var hashSet = new HashSet<TransportLayerConnection>();

        var expectedConnection = new TransportLayerConnection(
            sourceIpAddress: Parse(sourceIpAddress),
            destinationIpAddress: Parse(destinationIpAddress),
            sourcePort: sourcePort,
            destinationPort: destinationPort);

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
        var reverseDirectionConnection = new TransportLayerConnection(
            sourceIpAddress: Parse(SecondIpAddress),
            destinationIpAddress: Parse(FirstIpAddress),
            sourcePort: SecondPort,
            destinationPort: FirstPort);

        // Act
        var hashCode = _sut.GetHashCode();
        var reverseDirectionHashCode = reverseDirectionConnection.GetHashCode();

        // Assert
        hashCode.Should().Be(reverseDirectionHashCode);
    }

    [Fact]
    public void GetHashCode_IntOverflowIsHandled()
    {
        // Arrange
        var tcpConnection = new TransportLayerConnection(
            sourceIpAddress: Parse(FirstIpAddress),
            destinationIpAddress: Parse(SecondIpAddress),
            sourcePort: int.MaxValue,
            destinationPort: int.MaxValue - 1);

        // Act
        var hashCode = tcpConnection.GetHashCode();

        // Assert
        hashCode.Should().BeLessOrEqualTo(int.MaxValue);
    }
}