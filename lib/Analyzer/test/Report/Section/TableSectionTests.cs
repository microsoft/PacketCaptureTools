// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Section;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Section;

public class TableSectionTests
{
    [Fact]
    public void ShouldBeRendered_TableDataIsNull_ReturnsFalse()
    {
        // Arrange
        // Act
        var sut = new TableSectionFake(null!);

        // Assert
        sut.ShouldBeRendered.Should().BeFalse();
    }

    [Fact]
    public void ShouldBeRendered_TableDataIsEmptyList_ReturnsFalse()
    {
        // Arrange
        var tableData = new List<string[]>();

        // Act
        var sut = new TableSectionFake(tableData);

        // Assert
        sut.ShouldBeRendered.Should().BeFalse();
    }

    [Fact]
    public void ShouldBeRendered_TableDataHasElements_ReturnsFalse()
    {
        // Arrange
        string[] data = ["Table Data"];
        var tableData = new List<string[]> { data };

        // Act
        var sut = new TableSectionFake(tableData);

        // Assert
        sut.ShouldBeRendered.Should().BeTrue();
    }

    private class TableSectionFake(List<string[]> tableData) : TableSection
    {
        private readonly List<string[]> _tableData = tableData;

        protected override string NoDataMessage => "NoDataMessage";

        protected override string TableHeaderTitle => "TableHeaderTitle";

        protected override string TableHeaderDescription => "TableHeaderDescription";

        protected override string[] TableHeaders => ["Table Header"];

        protected override List<string[]> GetTableData()
        {
            return _tableData;
        }
    }
}