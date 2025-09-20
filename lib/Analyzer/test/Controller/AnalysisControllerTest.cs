// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Analysis.Connection.Transport;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet;
using Microsoft.PacketCapture.Analyzer.Analysis.Packet.Tcp;
using Microsoft.PacketCapture.Analyzer.Controller;
using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Packet;
using Microsoft.PacketCapture.Analyzer.Reader;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Report.Render;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using Microsoft.PacketCapture.Analyzer.Router;
using Moq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Controller;

public class AnalysisControllerTest
{
    private const string HelpText = "Visit this link for more information or to report any problems.";

    private static readonly byte[] PcapngBytes =
    [
        10, 13, 13, 10, 104, 0, 0, 0, 77, 60, 43, 26, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 21, 0, 87, 105, 110, 100, 111, 119, 115, 32, 49, 48, 32, 69, 110, 116, 101, 114, 112, 114, 105, 115, 101, 0, 0, 0, 2, 0, 17, 0, 76, 69, 78, 79, 86, 79, 32, 50, 48, 78, 55, 83, 49, 77, 82, 55, 51, 0, 0, 0, 4, 0, 14, 0, 80,
        97, 99, 107, 101, 116, 32, 77, 111, 110, 105, 116, 111, 114, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 1, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 6, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 176, 223, 5, 0, 128, 188, 90, 66, 66, 0, 0, 0, 66, 0, 0, 0, 184, 39, 235, 93, 88, 145, 60, 88, 194, 126, 31, 13, 8, 0, 69, 0, 0, 52, 219, 10, 64, 0, 128, 6, 0, 0, 192, 168, 0, 241,
        192, 168, 0, 21, 4, 139, 0, 80, 216, 193, 180, 136, 0, 0, 0, 0, 128, 2, 250, 240, 130, 125, 0, 0, 2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2, 0, 0, 100, 0, 0, 0, 6, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 176, 223, 5, 0, 138, 188, 90, 66, 66, 0, 0, 0, 66, 0, 0, 0, 184, 39, 235, 93, 88, 145, 60, 88, 194, 126, 31, 13, 8, 0, 69, 0, 0, 52, 219, 10, 64, 0, 128, 6, 0, 0, 192, 168, 0, 241,
        192, 168, 0, 21, 4, 139, 0, 80, 216, 193, 180, 136, 0, 0, 0, 0, 128, 2, 250, 240, 130, 125, 0, 0, 2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2, 0, 0, 100, 0, 0, 0, 6, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 176, 223, 5, 0, 141, 188, 90, 66, 66, 0, 0, 0, 66, 0, 0, 0, 184, 39, 235, 93, 88, 145, 60, 88, 194, 126, 31, 13, 8, 0, 69, 0, 0, 52, 219, 10, 64, 0, 128, 6, 0, 0, 192, 168, 0, 241, 
    ];

    [Fact]
    public void Constructor_SingleStream()
    {
        Stream stream = new MemoryStream();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        _ = new AnalysisController(config, stream);
    }

    [Fact]
    public void Constructor_MultipleStreams()
    {
        Stream stream = new MemoryStream();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        _ = new AnalysisController(config, stream, stream, stream, stream);
    }

    [Fact]
    public void Constructor_SingleFilePath()
    {
        var filePath = Path.GetTempFileName();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        _ = new AnalysisController(config, filePath);
    }

    [Fact]
    public void Constructor_MultipleFilePaths()
    {
        var filePath = Path.GetTempFileName();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        _ = new AnalysisController(config, filePath, filePath, filePath, filePath, filePath);
    }

    [Fact]
    public void Dispose_NoExecuteSingleReader()
    {
        var mockReader = new Mock<IReader>();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, [mockReader.Object]);
        analysisController.Dispose();

        mockReader.Verify(reader => reader.Dispose(), Times.Exactly(1));
    }

    [Fact]
    public void Dispose_NoExecuteMultipleReaders()
    {
        var mockReaders = Enumerable.Range(0, 10).Select(i => new Mock<IReader>()).ToArray();

        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, mockReaders.Select(mock => mock.Object));
        analysisController.Dispose();

        foreach (var mockReader in mockReaders)
        {
            mockReader.Verify(reader => reader.Dispose(), Times.Exactly(1));
        }
    }

    [Fact]
    public void Dispose_NoReaders()
    {
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, Enumerable.Empty<IReader>());
        analysisController.Dispose();
    }

    [Fact]
    public void Execute_InvokesDisposeSingleReader()
    {
        var mockReader = new Mock<IReader>();

        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, [mockReader.Object]);
        analysisController.Execute();

        mockReader.Verify(reader => reader.Dispose(), Times.Exactly(1));
    }

    [Fact]
    public void Execute_InvokesDisposeMultipleReaders()
    {
        var mockReaders = Enumerable.Range(0, 10).Select(i => new Mock<IReader>()).ToArray();

        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, mockReaders.Select(mock => mock.Object));
        analysisController.Execute();

        foreach (var mockReader in mockReaders)
        {
            mockReader.Verify(reader => reader.Dispose(), Times.Exactly(1));
        }
    }

    [Fact]
    public void Execute_SingleStream()
    {
        var mockAnalysis = new Mock<IPacketAnalysis>();

        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText) { PacketAnalyses = [mockAnalysis.Object] };
        var router = new PacketRouter(config);

        var analysisController = new AnalysisController(config, new MemoryStream(PcapngBytes));
        analysisController.Execute();

        mockAnalysis.Verify(analysis => analysis.Process(It.Is<CapturedPacket>(p => p.TransportSegment!.Payload.Length == 0)), Times.Exactly(2));
    }

    [Fact]
    public void Execute_MultipleStreams()
    {
        var mockAnalysis = new Mock<IPacketAnalysis>();

        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText) { PacketAnalyses = [mockAnalysis.Object] };
        var router = new PacketRouter(config);

        var analysisController = new AnalysisController(config, new MemoryStream(PcapngBytes), new MemoryStream(PcapngBytes), new MemoryStream(PcapngBytes));
        analysisController.Execute();

        mockAnalysis.Verify(analysis => analysis.Process(It.Is<CapturedPacket>(p => p.TransportSegment!.Payload.Length == 0)), Times.Exactly(6));
    }

    [Fact]
    public void Execute_NoReaders()
    {
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        var analysisController = new AnalysisController(config, Enumerable.Empty<IReader>());
        analysisController.Execute();
    }

    [Fact]
    public void Test_AnalysisController_Valid_File_Should_Return_Report()
    {
        // Given
        var renderer = new TextRenderer();
        var config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        Stream stream = new MemoryStream(PcapngBytes);
        var analysisController = new AnalysisController(config, stream);

        // When
        analysisController.Execute();

        // Then
        analysisController.Should().NotBeNull();
        config.TransportLayerAnalyses.Should().NotBeNull();
        config.PacketAnalyses.Should().NotBeNull();
        config.TransportLayerAnalyses.Count().Should().Be(3);
        config.PacketAnalyses.Count().Should().Be(4);

        config.Report.Render(renderer).ToString().Length.Should().BeGreaterThan(10);
    }

    [Fact]
    public void Test_AnalysisController_Valid_File_With_Cancelled_Cancellation_Token_Should_Throw_Exception()
    {
        // Given
        var renderer = new TextRenderer();
        IAnalysisConfiguration config = new TdsTrafficAnalysisConfiguration(new SessionMetadata(), HelpText);

        Stream stream = new MemoryStream(PcapngBytes);
        var analysisController = new AnalysisController(config, stream);
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        // When
        Action action = () => analysisController.Execute(cancellationTokenSource.Token);

        // Then
        action.Should().Throw<OperationCanceledException>();
    }

    [Fact]
    public void Test_AnalysisController_Null_Params_Should_Fail()
    {
        Action actionNullFile = () => _ = new AnalysisController(null!, filePaths: null!);
        Action actionNullStream = () => _ = new AnalysisController(null!, streams: null!);

        actionNullFile.Should().Throw<ArgumentNullException>();
        actionNullStream.Should().Throw<ArgumentNullException>();
    }

    private class TestSection(TcpPacketResetAnalysis analysis) : ISection
    {
        private readonly TcpPacketResetAnalysis _analysis = analysis;

        public void Render(IRenderer renderer)
        {
            foreach (var kv in _analysis.CountBySecond)
            {
                renderer.AddKeyValue(kv.Key.ToString(), kv.Value.ToString());
            }
        }
    }

    private class TestReport(ISection section, IEnumerable<IPacketAnalysis> packetAnalyses, IEnumerable<ITransportLayerConnectionAnalysis> connectionAnalyses) : IReport
    {
        private readonly ISection _section = section;

        public IEnumerable<IPacketAnalysis> PacketAnalyses { get; } = packetAnalyses;

        public IEnumerable<ITransportLayerConnectionAnalysis> ConnectionAnalyses { get; } = connectionAnalyses;

        public IEnumerable<ISection> Sections { get; } = [section];

        public TRenderer Render<TRenderer>(TRenderer renderer)
            where TRenderer : IRenderer
        {
            _section.Render(renderer);
            return renderer;
        }
    }
}