// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Table.Ascii;
using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Table.Ascii;

public class AsciiTableTest
{
    private static readonly string[] CaptureStartTime = ["Capture Start Time", "2022-04-21T15: 00:00"];
    private static readonly string[] CaptureEndTime = ["Capture End Time", "2022-04-21T15: 02:01"];
    private static readonly string[] CaptureDuration = ["Duration of Capture(HH:mm: ss)", "00:02:01"];
    private static readonly string[] User = ["Name of Creator", "<user@contoso.com>"];
    private static readonly string[] NumberOfFiles = ["Number of.pcap files", "2"];
    private static readonly string[] SizeOfFiles = ["Size of file(s)", "6MB, 10MB"];
    private static readonly string[] ReportType = ["Type of Report", "TCP Report(.txt)"];
    private static readonly string[] OperatingSystem = ["Operating System", "Windows 10"];
    private static readonly string[] NodeName = ["Node Name", "node1"];
    private static readonly string[] ClusterName = ["Cluster Name", "cluster1"];
    private static readonly string[] RegioName = ["Region Name", "us-east"];
    private static readonly string[] RequestId = ["Capture Request Id", "00000000-0000-0000-0000-000000000000"];
    private static readonly string[] ReportVersion = ["Report Version", "v1.0"];

    [Fact]
    public void Test_CreateTable_Should_Throw_For_Empty_List_Of_Headers()
    {
        // Arrange
        var headers = new List<string>();
        var rows = new List<string[]> { Array.Empty<string>() };

        // Act
        Action check = () =>
        {
            var table = AsciiTable.CreateTable(headers, rows);
        };

        // Assert
        check.Should().Throw<ArgumentException>($"Invalid parameters: '{nameof(headers)}' length should be > '0', actual value '{headers.Count}'.");
    }

    [Fact]
    public void Test_CreateTable_Should_Throw_For_Empty_List_Of_Rows()
    {
        // Arrange
        var headers = new List<string> { "1", "2", "3" };
        var rows = new List<string[]> { Array.Empty<string>() };

        // Act
        Action check = () =>
        {
            var table = AsciiTable.CreateTable(headers, rows);
        };

        // Assert
        check.Should().Throw<ArgumentException>($"Invalid parameters: '{nameof(rows)}' length at entry number {0} should equal to {headers.Count}, actual value '{rows[0].Length}'.");
    }

    [Fact]
    public void Test_CreateTable_Should_Throw_For_Null_List_Of_Headers_And_Rows()
    {
        // Arrange
        var headers = new List<string> { "1", "2", "3" };
        string[] values = ["1", "2", "3"];
        var rows = new List<string[]> { values, null! };

        // Act
        Action checkNullHeader = () =>
        {
            var table = AsciiTable.CreateTable(null!, null!);
        };
        Action checkNullRows = () =>
        {
            var table = AsciiTable.CreateTable(headers, null!);
        };
        Action checkNullRow = () =>
        {
            var table = AsciiTable.CreateTable(headers, rows);
        };

        // Assert
        checkNullHeader.Should().Throw<ArgumentNullException>(nameof(headers));
        checkNullRows.Should().Throw<ArgumentNullException>(nameof(rows));
        checkNullRow.Should().Throw<ArgumentNullException>($"Invalid parameters: '{nameof(rows)}' should not be null, at entry {1}'.");
    }

    [Fact]
    public void Test_CreateTable_Array_Of_Null_Values()
    {
        // Arrange
        var headers = new List<string> { null!, null!, null! };
        var rows = new List<string[]> { new string[] { null!, null!, null! } };

        // Act
        var table = AsciiTable.CreateTable(headers, rows);

        // Assert
        table.Should()
            .Be(
                """
                +---+---+---+
                | _ | _ | _ |
                +---+---+---+
                | _ | _ | _ |
                +---+---+---+
                """
            );
    }

    [Fact]
    public void Test_CreateTable_Should_Throw_For_Unequal_Header_And_Row_Length()
    {
        // Arrange
        var headers = new List<string> { "1", "2", "3" };
        var rows = new List<string[]> { Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>() };

        // Act
        Action check = () =>
        {
            var table = AsciiTable.CreateTable(headers, rows);
        };

        // Assert
        check.Should().Throw<ArgumentException>($"Invalid parameters: '{nameof(rows)}' length at entry number {0} should equal to {headers.Count}, actual value '{rows[0].Length}'.");
    }

    [Fact]
    public void Test_CreateTable_Basic_Array_Of_Values()
    {
        // Arrange
        var headers = new List<string> { "1", "2", "3" };

        string[] values1 = ["4", "5", "6"];
        string[] values2 = ["7", "8", "9"];
        string[] values3 = ["10", "11", "12"];

        var rows = new List<string[]>
        {
            values1,
            values2,
            values3,
        };

        // Act
        var table = AsciiTable.CreateTable(headers, rows);

        // Assert
        table.Should()
            .Be(
                """
                +----+----+----+
                | 1  | 2  | 3  |
                +----+----+----+
                | 4  | 5  | 6  |
                | 7  | 8  | 9  |
                | 10 | 11 | 12 |
                +----+----+----+
                """
            );
    }



    [Fact]
    public void Test_MetadataTable_Align_To_Center()
    {
        // Arrange
        var headers = new List<string> { "Name", "Value" };
        var rows = new List<string[]>
        {
            CaptureStartTime,
            CaptureEndTime,
            CaptureDuration,
            User,
            NumberOfFiles,
            SizeOfFiles,
            ReportType,
            OperatingSystem,
            NodeName,
            ClusterName,
            RegioName,
            RequestId,
            ReportVersion,
        };

        // Act
        var table = AsciiTable.CreateTable(headers, rows, true);

        // Assert
        table.Should()
            .Be(
                """
                +--------------------------------+--------------------------------------+
                |              Name              |                 Value                |
                +--------------------------------+--------------------------------------+
                |       Capture Start Time       |         2022-04-21T15: 00:00         |
                |        Capture End Time        |         2022-04-21T15: 02:01         |
                | Duration of Capture(HH:mm: ss) |               00:02:01               |
                |         Name of Creator        |          <user@contoso.com>          |
                |      Number of.pcap files      |                   2                  |
                |         Size of file(s)        |               6MB, 10MB              |
                |         Type of Report         |           TCP Report(.txt)           |
                |        Operating System        |              Windows 10              |
                |            Node Name           |                 node1                |
                |          Cluster Name          |               cluster1               |
                |           Region Name          |                us-east               |
                |       Capture Request Id       | 00000000-0000-0000-0000-000000000000 |
                |         Report Version         |                 v1.0                 |
                +--------------------------------+--------------------------------------+
                """
            );
    }

    [Fact]
    public void Test_MetadataTable_Align_To_Left()
    {
        // Arrange
        var headers = new List<string> { "Name", "Value" };
        var rows = new List<string[]>
        {
            CaptureStartTime,
            CaptureEndTime,
            CaptureDuration,
            User,
            NumberOfFiles,
            SizeOfFiles,
            ReportType,
            OperatingSystem,
            NodeName,
            ClusterName,
            RegioName,
            RequestId,
            ReportVersion,
        };

        // Act
        var table = AsciiTable.CreateTable(headers, rows);

        // Assert
        table.Should()
            .Be(
                """
                +--------------------------------+--------------------------------------+
                | Name                           | Value                                |
                +--------------------------------+--------------------------------------+
                | Capture Start Time             | 2022-04-21T15: 00:00                 |
                | Capture End Time               | 2022-04-21T15: 02:01                 |
                | Duration of Capture(HH:mm: ss) | 00:02:01                             |
                | Name of Creator                | <user@contoso.com>                   |
                | Number of.pcap files           | 2                                    |
                | Size of file(s)                | 6MB, 10MB                            |
                | Type of Report                 | TCP Report(.txt)                     |
                | Operating System               | Windows 10                           |
                | Node Name                      | node1                                |
                | Cluster Name                   | cluster1                             |
                | Region Name                    | us-east                              |
                | Capture Request Id             | 00000000-0000-0000-0000-000000000000 |
                | Report Version                 | v1.0                                 |
                +--------------------------------+--------------------------------------+
                """
            );
    }
}