// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section.Help;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section;

public class HelpSectionTest
{
    private const string HelpText = "Visit this link for more information or to report issues and submit feedback.";
    private readonly HelpSection _sut;

    private readonly TextRenderer _textRenderer;

    public HelpSectionTest()
    {
        _textRenderer = new TextRenderer();
        _sut = new HelpSection(HelpText);
    }

    [Fact]
    public void Test_Section()
    {
        // Arrange
        var expectedResult = @"Help
----

Visit this link for more information or to report issues and submit feedback.

";
        // Act
        _sut.Render(_textRenderer);
        var result = _textRenderer.ToString();

        // Assert
        result.Should().Be(expectedResult);
    }
}