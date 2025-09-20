// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Render;

public class TextRendererTest
{
    private readonly TextRenderer _textRenderer;

    public TextRendererTest()
    {
        _textRenderer = new TextRenderer();
    }

    [Fact]
    public void Test_AddKeyValue_To_See_If_Pair_Is_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddKeyValue("TCP Total Reset Analysis", "4");

        // Assert
        _textRenderer.ToString().Should().Be(
            """
            TCP Total Reset Analysis: 4

            """);
    }

    [Fact]
    public void Test_AddKeyValue_To_See_If_Multiple_Pairs_Is_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddKeyValue("TCP Total Reset Analysis", "2");
        _textRenderer.AddKeyValue("TCP Total Retransmits Analysis", "3");
        _textRenderer.AddKeyValue("Per Stateful Protocol Packet Counters", "4");

        // Assert
        _textRenderer.ToString()
            .Should()
            .Be(
                """
                TCP Total Reset Analysis: 2
                TCP Total Retransmits Analysis: 3
                Per Stateful Protocol Packet Counters: 4
                
                """);
    }

    [Fact]
    public void Test_AdddKeyValue_Null_Parameters_Should_Not_Be_Valid()
    {
        // Arrange
        // Act
        Action checkAddAllNull = () => { _textRenderer.AddKeyValue(null!, null!); };
        Action checkAddKey = () => { _textRenderer.AddKeyValue(null!, string.Empty); };
        Action checkAddValue = () => { _textRenderer.AddKeyValue(string.Empty, null!); };

        // Assert
        checkAddAllNull.Should().Throw<ArgumentNullException>();
        checkAddKey.Should().Throw<ArgumentNullException>();
        checkAddValue.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Test_AddHeader_To_See_If_Header_Is_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddHeader("TCP Total Reset Analysis", "A graph showing the total number of TCP connection resets over the period of the packet capture operation.");

        // Assert
        _textRenderer.ToString().Should().Be(
            """
            [TCP Total Reset Analysis]
            A graph showing the total number of TCP connection resets over the period of the packet capture operation.
            
            
            """);
            
    }

    [Fact]
    public void Test_AddHeader_To_See_If_Multiple_Header_Is_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddHeader("TCP Total Reset Analysis", "A graph showing the total number of TCP connection resets over the period of the packet capture operation.");
        _textRenderer.AddHeader("TCP Total Retransmits Analysis", "A graph showing the total number of TCP retranmission attempts over the period of the packet capture operation.");
        _textRenderer.AddHeader("Per Stateful Protocol Packet Counters", "A Total breakdown of all captured packets metrics by Stateful Protocol.");

        // Assert
        _textRenderer.ToString()
            .Should()
            .Be(
                """
                [TCP Total Reset Analysis]
                A graph showing the total number of TCP connection resets over the period of the packet capture operation.

                [TCP Total Retransmits Analysis]
                A graph showing the total number of TCP retranmission attempts over the period of the packet capture operation.

                [Per Stateful Protocol Packet Counters]
                A Total breakdown of all captured packets metrics by Stateful Protocol.
                
                
                """);
    }

    [Fact]
    public void Test_AddHeader_Null_Parameters_Should_Be_Empty()
    {
        // Arrange
        // Act
        _textRenderer.AddHeader(header: null, headerText: null);
        _textRenderer.AddHeader(header: null, headerText: string.Empty);
        _textRenderer.AddHeader(header: string.Empty, headerText: null);

        // Assert
        _textRenderer.ToString().Should().Be(string.Empty);
    }

    [Fact]
    public void Test_AddSectionHeader_Basic_Case_Should_Be_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddSectionTitle("Session Metadata Section");
        _textRenderer.AddSectionTitle("Throughput Section");
        _textRenderer.AddSectionTitle("Tcp Packet Reset Graph Section");

        // Assert
        _textRenderer.ToString()
            .Should()
            .Be(
                """
                Session Metadata Section
                ------------------------
                
                Throughput Section
                ------------------

                Tcp Packet Reset Graph Section
                ------------------------------
                

                """);
    }

    [Fact]
    public void Test_AddSectionHeader_Null_Parameters_Should_Not_Be_Valid()
    {
        // Arrange
        // Act
        Action checkNull = () => { _textRenderer.AddSectionTitle(title: null!); };

        // Assert
        checkNull.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Test_ToString_Should_Be_Valid()
    {
        // Arrange
        // Act
        _textRenderer.AddHeader(header: null, headerText: null);
        var renderResult = _textRenderer.ToString();

        // Assert
        _textRenderer.Should().NotBeNull();
        renderResult.Should().Be(string.Empty);
    }

    [Fact]
    public void Test_ToString_Null_Parameters_Should_Not_Be_Valid()
    {
        // Arrange
        var textRendererEmpty = new TextRenderer();

        // Act
        _textRenderer.AddKeyValue("TCP Total Reset Analysis", "4");

        // Assert
        _textRenderer.ToString().Should().Be(
            """
            TCP Total Reset Analysis: 4

            """);
        textRendererEmpty.ToString().Should().Be(string.Empty);
    }
}