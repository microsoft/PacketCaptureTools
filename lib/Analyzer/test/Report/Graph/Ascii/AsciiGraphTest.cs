// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using FluentAssertions;
using Microsoft.PacketCapture.Analyzer.Report.Graph;
using Microsoft.PacketCapture.Analyzer.Report.Graph.Ascii;
using Xunit;

namespace Microsoft.PacketCapture.Analyzer.Test.Report.Graph.Ascii;

public class AsciiGraphTest
{
    [Fact]
    public void Test_Plot_With_Empty_Array()
    {
        // Arrange
        var xaxis = new long[0];
        var yaxis = new long[0];

        // Act
        var graph = AsciiGraph.Plot(new GraphData(string.Empty, string.Empty, xaxis, yaxis), DateTimeToHoursMinutes, YToString);

        // Assert
        graph.Should()
            .Be(
                "Insufficient packets supplied. At least two packets are needed to build a graph, actual number of packets: 0."
            );
    }

    [Fact]
    public void Test_Plot()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65, 071, 90, 95, 119, 125, 130, 140, 150, 145, 155, 200, 205];
        long[] y = [00, 20, 30, 20, 80, 145, 00, 130, 60, 00, 000, 000, 000, 050, 040, 040, 040, 200, 030];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME PERIOD OF DAY (HH:MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            DateTimeToHoursMinutes,
            YToString);

        // Assert
        graph.Should()
            .Be(
                """
                   200┤                                       ╭╮    
                   190┤                                       ││    
                   180┤                                       ││    
                   170┤                                       ││    
                   160┤                                       ││    
                T  150┤                                       ││    
                C  140┤          ╭╮                           ││    
                P  130┤          ││ ╭╮                        ││    
                   120┤          ││ ││                        ││    
                R  110┤          ││ ││                        ││    
                e  100┤          ││ ││                        ││    
                s   90┤          ││ ││                        ││    
                e   80┤         ╭╯│ ││                        ││    
                t   70┤         │ │ ││                        ││    
                s   60┤         │ │ ││  ╭╮                    ││    
                    50┤  ╭╮     │ │ ││  ││        ╭╮          ││    
                    40┤  ││     │ │ ││  ││        │╰──╮       ││    
                    30┤  ││     │ │ ││  ││        │   │       │╰╮   
                    20┤ ╭╯│     │ │ ││  ││        │   │       │ │   
                    10┤ │ │     │ │ ││  ││        │   │       │ │   
                     0┤─╯ ╰     ╯ ╰ ╯╰  ╯╰─   ─ ──╯   ╰       ╯ ╰   
                       ------------|-----------|-----------|--------
                     00:00       01:00       02:00       03:00      
                             TIME PERIOD OF DAY (HH:MM)             
                """
            );
    }

    [Fact]
    public void Test_Plot_With_Few_Points_Should_Use_Minimum_Size()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65];
        long[] y = [00, 20, 30, 20, 80, 145, 00];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME PERIOD OF DAY (HH:MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            DateTimeToHoursMinutes,
            YToString);

        // Assert
        graph.Should()
            .Be(
                """
                   144┤          ╭╮                              
                   136┤          ││                              
                   128┤          ││                              
                   120┤          ││                              
                T  112┤          ││                              
                C  104┤          ││                              
                P   96┤          ││                              
                    88┤          ││                              
                R   80┤         ╭╯│                              
                e   72┤         │ │                              
                s   64┤         │ │                              
                e   56┤         │ │                              
                t   48┤         │ │                              
                s   40┤  ╭╮     │ │                              
                    32┤  ││     │ │                              
                    24┤  ││     │ │                              
                    16┤ ╭╯│     │ │                              
                     8┤ │ │     │ │                              
                     0┤─╯ ╰     ╯ ╰ ─                            
                       ------------|-----------|-----------|-----
                     00:00       01:00       02:00       03:00   
                           TIME PERIOD OF DAY (HH:MM)            
                """);
    }

    [Fact]
    public void Test_Plot_With_Small_Y_Range_Should_Use_Minimum_Size()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65];
        long[] y = [00, 00, 00, 00, 00, 000, 01];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME PERIOD OF DAY (HH:MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            DateTimeToHoursMinutes,
            YToString);

        // Assert
        graph.Should()
            .Be(
                """
                T  10┤                                          
                C   9┤                                          
                P   8┤                                          
                    7┤                                          
                R   6┤                                          
                e   5┤                                          
                s   4┤                                          
                e   3┤                                          
                t   2┤                                          
                s   1┤            ╭╮                            
                    0┤─ ──      ──╯╰                            
                      ------------|-----------|-----------|-----
                    00:00       01:00       02:00       03:00   
                           TIME PERIOD OF DAY (HH:MM)           
                """);
    }

    [Fact]
    public void Test_Plot_With_Two_Hour_xInterval()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65, 071, 90, 95, 119, 125, 130, 140, 150, 145, 155, 200, 205];
        long[] y = [00, 20, 30, 20, 80, 145, 00, 130, 60, 00, 000, 000, 000, 050, 040, 040, 040, 200, 030];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME PERIOD OF DAY (HH:MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            DateTimeToHoursMinutes,
            YToString,
            200,
            20,
            120);

        // Assert
        graph.Should()
            .Be(
                """
                   200┤                                       ╭╮    
                   190┤                                       ││    
                   180┤                                       ││    
                   170┤                                       ││    
                   160┤                                       ││    
                T  150┤                                       ││    
                C  140┤          ╭╮                           ││    
                P  130┤          ││ ╭╮                        ││    
                   120┤          ││ ││                        ││    
                R  110┤          ││ ││                        ││    
                e  100┤          ││ ││                        ││    
                s   90┤          ││ ││                        ││    
                e   80┤         ╭╯│ ││                        ││    
                t   70┤         │ │ ││                        ││    
                s   60┤         │ │ ││  ╭╮                    ││    
                    50┤  ╭╮     │ │ ││  ││        ╭╮          ││    
                    40┤  ││     │ │ ││  ││        │╰──╮       ││    
                    30┤  ││     │ │ ││  ││        │   │       │╰╮   
                    20┤ ╭╯│     │ │ ││  ││        │   │       │ │   
                    10┤ │ │     │ │ ││  ││        │   │       │ │   
                     0┤─╯ ╰     ╯ ╰ ╯╰  ╯╰─   ─ ──╯   ╰       ╯ ╰   
                       ------------------------|--------------------
                     00:00                   02:00                  
                             TIME PERIOD OF DAY (HH:MM)             
                """);
    }

    [Fact]
    public void Test_Plot_With_Minimum_Height_And_Minimum_Width()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65, 071, 90, 95, 119, 125, 130, 140, 150, 145, 155, 200, 205];
        long[] y = [00, 20, 30, 20, 80, 145, 00, 130, 60, 00, 000, 000, 000, 050, 040, 040, 040, 200, 030];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME PERIOD OF DAY (HH:MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            z => z.ToString(),
            YToString,
            40,
            40,
            100);

        // Assert
        graph.Should()
            .Be(
                """
                   200┤                                ╭╮       
                   190┤                                ││       
                   180┤                                ││       
                   170┤                                ││       
                   160┤                                ││       
                T  150┤                                ││       
                C  140┤        ╭╮                      ││       
                P  130┤        ││╭╮                    ││       
                   120┤        ││││                    ││       
                R  110┤        ││││                    ││       
                e  100┤        ││││                    ││       
                s   90┤        ││││                    ││       
                e   80┤       ╭╯│││            ╭╮      ││       
                t   70┤       │ │││            ││      ││       
                s   60┤       │ │││  ╭╮        ││      ││       
                    50┤ ╭╮    │ │││  ││      ╭╮││      ││       
                    40┤ ││    │ │││  ││      │╰╯│      ││       
                    30┤ ││    │ │││  ││      │  │      │╰╮      
                    20┤╭╯│    │ │││  ││      │  │      │ │      
                    10┤│ │    │ │││  ││      │  │      │ │      
                     0┤╯ ╰    ╯ ╰╯╰  ╯╰   ───╯  ╰      ╯ ╰      
                       ----------------|---------------|--------
                       0              96              192       
                           TIME PERIOD OF DAY (HH:MM)           
                """);
    }

    [Fact]
    public void Test_Plot_With_Below_Minimum_Height_And_Width_Should_Use_Default_Size()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65, 071, 90, 95, 119, 125, 130, 140, 150, 145, 155, 200, 205];
        long[] y = [00, 20, 30, 20, 80, 145, 00, 130, 60, 00, 000, 000, 000, 050, 040, 040, 040, 200, 030];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME (MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            z => z.ToString(),
            YToString,
            5,
            5,
            100);

        // Assert
        graph.Should()
            .Be(
                """
                   200┤                                       ╭╮   
                   190┤                                       ││   
                   180┤                                       ││   
                   170┤                                       ││   
                   160┤                                       ││   
                T  150┤                                       ││   
                C  140┤          ╭╮                           ││   
                P  130┤          ││ ╭╮                        ││   
                   120┤          ││ ││                        ││   
                R  110┤          ││ ││                        ││   
                e  100┤          ││ ││                        ││   
                s   90┤          ││ ││                        ││   
                e   80┤         ╭╯│ ││                        ││   
                t   70┤         │ │ ││                        ││   
                s   60┤         │ │ ││  ╭╮                    ││   
                    50┤  ╭╮     │ │ ││  ││        ╭╮          ││   
                    40┤  ││     │ │ ││  ││        │╰──╮       ││   
                    30┤  ││     │ │ ││  ││        │   │       │╰╮  
                    20┤ ╭╯│     │ │ ││  ││        │   │       │ │  
                    10┤ │ │     │ │ ││  ││        │   │       │ │  
                     0┤─╯ ╰     ╯ ╰ ╯╰  ╯╰─   ─ ──╯   ╰       ╯ ╰  
                       --------------------|-------------------|---
                       0                  100                 200  
                                     TIME (MM)                     
                """);
    }

    [Fact]
    public void Test_Plot_With_Wide_Range_Of_Data()
    {
        // Arrange
        long[] x = [00, 10, 15, 17, 50, 055, 65, 071, 90, 95, 119, 125, 130, 140, 150, 145, 155, 200, 605];
        long[] y = [00, 20, 30, 20, 80, 145, 00, 130, 60, 00, 000, 000, 000, 050, 040, 040, 040, 200, 030];

        // Act
        var graph = AsciiGraph.Plot(
            new GraphData(
                xAxisLabel: "TIME (MM)",
                yAxisLabel: "TCP Resets",
                xAxisData: x,
                yAxisData: y),
            z => z.ToString(),
            YToString,
            70,
            25,
            100);

        // Assert
        graph.Should()
            .Be(
                """
                   200┤                     ╭╮                                                
                   190┤                     ││                                                
                   180┤                     ││                                                
                   170┤                     ││                                                
                   160┤                     ││                                                
                T  150┤                     ││                                                
                C  140┤     ╭╮              ││                                                
                P  130┤     │╰╮             ││                                                
                   120┤     │ │             ││                                                
                R  110┤     │ │             ││                                                
                e  100┤     │ │             ││                                                
                s   90┤     │ │             ││                                                
                e   80┤    ╭╯ │       ╭╮    ││                                                
                t   70┤╭╮  │  │       ││    ││                                                
                s   60┤││  │  │ ╭╮    ││    ││                                                
                    50┤││  │  │ ││   ╭╯│    ││                                                
                    40┤││  │  │ ││   │ ╰╮   ││                                                
                    30┤││  │  │ ││   │  │   ││                                           ╭╮   
                    20┤││  │  │ ││   │  │   ││                                           ││   
                    10┤││  │  │ ││   │  │   ││                                           ││   
                     0┤╯╰  ╯  ╰ ╯╰  ─╯  ╰   ╯╰                                           ╯╰   
                       -----------|----------|----------|----------|----------|----------|----
                       0         99         198        297        396        495        594   
                                                   TIME (MM)                                  
                """);
    }

    public static string DateTimeToHoursMinutes(long xValue)
    {
        return (xValue / 60 % 24).ToString().PadLeft(2, '0') + ":" + (xValue % 60).ToString().PadLeft(2, '0');
    }

    public static string YToString(long y)
    {
        return y.ToString();
    }
}