// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Packet counters composite section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="PacketCountersCompositeSection" /> class.
/// </remarks>
/// <param name="subSections">Sub sections to use in this composite section.</param>
public class PacketCountersCompositeSection(
    GlobalPacketCountersTableSection globalPacketCountersTableSection,
    PacketCountersPerProtocolCompositeSection packetCountersPerProtocolCompositeSection,
    ThroughputPacketTableSection throughputPacketTableSection,
    PerIpPacketCountersTableSection perIpPacketCountersTableSection) : CompositeSection
{
    public PacketCountersCompositeSection(IAnalysisProvider analysisProvider)
        : this(
              new GlobalPacketCountersTableSection(analysisProvider),
              new PacketCountersPerProtocolCompositeSection(analysisProvider),
              new ThroughputPacketTableSection(analysisProvider),
              new PerIpPacketCountersTableSection(analysisProvider))
    {
    }

    /// <inheritdoc />
    public override IEnumerable<ISection> Subsections { get; } = [
            globalPacketCountersTableSection,
            packetCountersPerProtocolCompositeSection,
            throughputPacketTableSection,
            perIpPacketCountersTableSection
        ];

    /// <inheritdoc />
    protected override string SectionTitle => "Packet Counters";
}
