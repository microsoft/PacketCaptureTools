// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using System;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Extensions;

public class DateTimeExtensionsTests
{
    [Fact]
    public void UpToSecond_DateTimeMin()
    {
        Assert.Equal(DateTime.MinValue, DateTime.MinValue.TruncateToSeconds());
    }

    [Fact]
    public void UpToSecond_DateTimeMax()
    {
        Assert.NotEqual(DateTime.MaxValue, DateTime.MaxValue.TruncateToSeconds());
    }

    [Fact]
    public void UpToSecond_TwoDifferentTimestamps()
    {
        var timestamp1 = new DateTime(2022, 06, 17, 11, 16, 01, 69);
        var timestamp2 = new DateTime(2022, 06, 17, 11, 16, 01, 420);
        Assert.Equal(timestamp1.TruncateToSeconds(), timestamp2.TruncateToSeconds());
    }

    [Fact]
    public void UpToSecond_NoMilliseconds()
    {
        var timestamp1 = new DateTime(2022, 06, 17, 11, 16, 01, 69);
        var timestamp2 = new DateTime(2022, 06, 17, 11, 16, 01, 420);

        Assert.Equal(0, timestamp1.TruncateToSeconds().Millisecond);
        Assert.Equal(0, timestamp2.TruncateToSeconds().Millisecond);
    }

    [Fact]
    public void ToStringFormat_Format()
    {
        var timestamp1 = new DateTime(2022, 06, 17, 11, 16, 01, 999);

        Assert.Equal("2022-06-17 11:16:01.9990000", timestamp1.ToStringFormat());
    }
}