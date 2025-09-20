// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Metadata;
using Moq;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section;

public class SessionMetadataSectionTest
{
    [Fact]
    public void Test_SessionMetadataSection_Valid_Params_Should_Pass()
    {
        // Given
        var mockRenderer = new Mock<IRenderer>();
        var sessionMetadata = new SessionMetadata();
        var sessionMetadataSection = new SessionMetadataSection(sessionMetadata, null);

        // When
        Action action = () => sessionMetadataSection.Render(mockRenderer.Object);

        // Then
        action.Should().NotThrow();
    }

    [Fact]
    public void Test_SessionMetadataSection_Null_Params_Should_Pass()
    {
        // When
        Action action = () => _ = new SessionMetadataSection(null!, null);

        // Then
        action.Should().Throw<ArgumentNullException>();
    }
}