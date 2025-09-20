// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Analysis;
using System.Collections.Generic;

namespace Microsoft.PacketCapture.Analyzer.Report.Section.Packet;

/// <summary>
/// Packet counters per protocol composite section.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="PacketCountersPerProtocolCompositeSection" /> class.
/// </remarks>
public class PacketCountersPerProtocolCompositeSection(
    NetworkLayerPacketCountersPerProtocolTableSection networkLayerPacketCountersPerProtocolTableSection,
    TransportLayerPacketCountersPerProtocolTableSection transportLayerPacketCountersPerProtocolTableSection) : CompositeSection
{
    public PacketCountersPerProtocolCompositeSection(IAnalysisProvider analysisProvider)
        : this(
              new NetworkLayerPacketCountersPerProtocolTableSection(analysisProvider),
              new TransportLayerPacketCountersPerProtocolTableSection(analysisProvider))
    {
    }

    /// <inheritdoc />
    public override IEnumerable<ISection> Subsections { get; } = [
            networkLayerPacketCountersPerProtocolTableSection,
            transportLayerPacketCountersPerProtocolTableSection,
        ];

    /// <inheritdoc />
    protected override string CompositeHeaderTitle => "Packet Counters per protocol";

    /// <inheritdoc />
    protected override string CompositeHeaderDescription => "The percent and count of packets received / sent for each protocol.";
}
