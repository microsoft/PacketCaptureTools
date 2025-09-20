// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report;
using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report;

public class SessionMetadataTest
{
    [Fact]
    public void Constructor_NullParams_ShouldPassWithDefaultCaptureAddress()
    {
        // Arrange
        var expectedCapturedAddresses = new HashSet<IPAddress> { IPAddress.Loopback };

        // Act
        var sut = new SessionMetadata(
            startCaptureTime: null,
            endCaptureTime: null,
            captureAddresses: expectedCapturedAddresses,
            additionalMetadata: null);

        // Assert
        sut.StartCaptureTime.Should().BeNull();
        sut.EndCaptureTime.Should().BeNull();
        sut.CaptureDuration.Should().BeNull();
        sut.CaptureAddresses.Should().Equal(expectedCapturedAddresses);
        sut.AdditionalMetadata.Should().NotBeNull();
        sut.AdditionalMetadata.Count.Should().Be(0);
    }

    [Fact]
    public void Constructor_EmptyParams_ShouldPassWithDefaultCaptureAddress()
    {
        // Arrange
        var expectedCapturedAddresses = new HashSet<IPAddress> { IPAddress.Loopback };

        // Act
        var sut = new SessionMetadata(captureAddresses: expectedCapturedAddresses);

        // Assert
        sut.StartCaptureTime.Should().BeNull();
        sut.EndCaptureTime.Should().BeNull();
        sut.CaptureDuration.Should().BeNull();
        sut.CaptureAddresses.Should().Equal(expectedCapturedAddresses);
        sut.AdditionalMetadata.Should().NotBeNull();
        sut.AdditionalMetadata.Count.Should().Be(0);
    }

    [Fact]
    public void Constructor_EmptyCaptureAddresses_ShouldPassWithDefaultCaptureAddress()
    {
        // Arrange
        var expectedCapturedAddresses = new HashSet<IPAddress> { IPAddress.Loopback };

        // Act
        var sut = new SessionMetadata(captureAddresses: expectedCapturedAddresses);

        // Assert
        sut.StartCaptureTime.Should().BeNull();
        sut.EndCaptureTime.Should().BeNull();
        sut.CaptureDuration.Should().BeNull();
        sut.CaptureAddresses.Should().Equal(expectedCapturedAddresses);
        sut.AdditionalMetadata.Should().NotBeNull();
        sut.AdditionalMetadata.Count.Should().Be(0);
    }

    [Fact]
    public void Constructor_ValidStartAndEndCaptureTimes_ExpectCaptureDurationValue()
    {
        // Arrange
        var expectedCapturedAddresses = new HashSet<IPAddress> { IPAddress.Loopback };

        // Act
        var sut = new SessionMetadata(
            startCaptureTime: DateTime.Parse("1970-01-01 00:00:00"),
            endCaptureTime: DateTime.Parse("1970-01-01 00:20:00"), 
            captureAddresses: expectedCapturedAddresses);

        // Assert
        sut.StartCaptureTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00"));
        sut.EndCaptureTime.Should().Be(DateTime.Parse("1970-01-01 00:20:00"));
        sut.CaptureDuration.Should().Be(TimeSpan.Parse("00:20:00"));
        sut.CaptureAddresses.Should().Equal(expectedCapturedAddresses);
        sut.AdditionalMetadata.Should().NotBeNull();
        sut.AdditionalMetadata.Count.Should().Be(0);
    }

    [Fact]
    public void Constructor_EndCaptureTimeLowerThanStartCaptureTime_ExpectArgumentException()
    {
        // Arrange
        // Act
        Action sut = () =>
        {
            _ = new SessionMetadata(
                startCaptureTime: DateTime.Parse("1970-01-01 00:00:00"),
                endCaptureTime: DateTime.Parse("1969-01-01 00:00:00"));
        }; 

        // Assert
        sut.Should()
            .Throw<ArgumentException>()
            .WithMessage($"{nameof(SessionMetadata.EndCaptureTime)} cannot be a lower value than {nameof(SessionMetadata.StartCaptureTime)}.");
    }

    [Fact]
    public void Constructor_ValidParams_ShouldPassWithExpectedValues()
    {
        // Arrange
        IDictionary<string, string> expectedAdditionalMetadata = new Dictionary<string, string>
        {
            { "Operating System", "Windows 10" },
            { "Node name", "node1" },
            { "Cluster name", "cluster1" },
        };
        var expectedCapturedAddresses = new HashSet<IPAddress> 
        {
            IPAddress.Parse("192.0.0.9"),
            IPAddress.Parse("0:0:0:0:0:0:0:9"), 
        };

        // Act
        var sut = new SessionMetadata(
            startCaptureTime: DateTime.Parse("1970-01-01 00:00:00"),
            endCaptureTime: DateTime.Parse("1970-01-01 00:20:00"),
            captureAddresses: new HashSet<IPAddress> { IPAddress.Parse("192.0.0.9"), IPAddress.Parse("0:0:0:0:0:0:0:9") },
            additionalMetadata: new Dictionary<string, string> 
            {
                { "Operating System", "Windows 10" },
                { "Node name", "node1" },
                { "Cluster name", "cluster1" },
            });

        // Assert
        sut.StartCaptureTime.Should().Be(DateTime.Parse("1970-01-01 00:00:00"));
        sut.EndCaptureTime.Should().Be(DateTime.Parse("1970-01-01 00:20:00"));
        sut.CaptureDuration.Should().Be(TimeSpan.Parse("00:20:00"));
        sut.CaptureAddresses.Should().Equal(expectedCapturedAddresses);
        sut.AdditionalMetadata.Should().Equal(expectedAdditionalMetadata);
        sut.AdditionalMetadata.Count.Should().Be(3);
    }
}