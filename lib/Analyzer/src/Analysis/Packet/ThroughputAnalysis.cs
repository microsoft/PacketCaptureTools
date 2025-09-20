// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Extensions;
using Microsoft.PacketCapture.Analyzer.Packet;
using System;

namespace Microsoft.PacketCapture.Analyzer.Analysis.Packet;

/// <summary>
/// Analysis to determine Throughput of packets.
/// </summary>
public class ThroughputAnalysis : IPacketAnalysis
{
    private bool _partialStartSlotSkipped;

    private long _minNumberOfPackets = long.MaxValue;
    private long _maxNumberOfPackets;

    private long _minSpeedOfDataTransfer = long.MaxValue;
    private long _maxSpeedOfDataTransfer;

    private long _currentNumberOfPackets;
    private long _currentSizeOfPackets;

    private DateTime _currentTimestampSecond = DateTime.MaxValue;
    private DateTime _earliestPacketTime = DateTime.MaxValue;
    private DateTime _latestPacketTime;

    /// <summary>
    /// Initializes a new instance of the <see cref="ThroughputAnalysis" /> class.
    /// </summary>
    public ThroughputAnalysis()
        : this(default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ThroughputAnalysis" /> class.
    /// </summary>
    /// <param name="partialStartSlotSkipped">Initial partial start slot skipped.</param>
    /// <param name="fullTimeSlotExists">Initial full time slot exists.</param>
    /// <param name="minNumberOfPackets">Initial min number of packets.</param>
    /// <param name="maxNumberOfPackets">Initial max number of packets.</param>
    /// <param name="minSpeedOfDataTransfer">Initial min speed of data transfer.</param>
    /// <param name="maxSpeedOfDataTransfer">Initial max speed of data transfer.</param>
    /// <param name="currentNumberOfPackets">Initial current number of packets.</param>
    /// <param name="currentSizeOfPackets">Initial current size of packets.</param>
    /// <param name="currentTimestampSecond">Initial current timestamp second.</param>
    /// <param name="earliestPacketTime">Initial earliest packet time.</param>
    /// <param name="latestPacketTime">Initial latest packet time.</param>
    /// <param name="totalNumberOfPackets">Initial total number of packets.</param>
    /// <param name="totalAmountOfBytesPassed">Initial total amount of bytes passed.</param>
    internal ThroughputAnalysis(
        bool partialStartSlotSkipped = default,
        bool fullTimeSlotExists = default,
        long minNumberOfPackets = long.MaxValue,
        long maxNumberOfPackets = default,
        long minSpeedOfDataTransfer = long.MaxValue,
        long maxSpeedOfDataTransfer = default,
        long currentNumberOfPackets = default,
        long currentSizeOfPackets = default,
        DateTime? currentTimestampSecond = null,
        DateTime? earliestPacketTime = null,
        DateTime? latestPacketTime = null,
        long totalNumberOfPackets = default,
        long totalAmountOfBytesPassed = default)
    {
        _partialStartSlotSkipped = partialStartSlotSkipped;
        _minNumberOfPackets = minNumberOfPackets;
        _maxNumberOfPackets = maxNumberOfPackets;
        _minSpeedOfDataTransfer = minSpeedOfDataTransfer;
        _maxSpeedOfDataTransfer = maxSpeedOfDataTransfer;
        _currentNumberOfPackets = currentNumberOfPackets;
        _currentSizeOfPackets = currentSizeOfPackets;
        _currentTimestampSecond = currentTimestampSecond ?? DateTime.MaxValue;
        _earliestPacketTime = earliestPacketTime ?? DateTime.MaxValue;
        _latestPacketTime = latestPacketTime ?? default;
        TotalNumberOfPackets = totalNumberOfPackets;
        TotalAmountOfBytesPassed = totalAmountOfBytesPassed;
    }

    /// <summary>
    /// Gets the average number of packets per second.
    /// </summary>
    public double AverageNumberOfPackets =>
        PacketCaptureDuration != TimeSpan.Zero
            ? TotalNumberOfPackets / PacketCaptureDuration.TotalSeconds
            : TotalNumberOfPackets;

    /// <summary>
    /// Gets the average payload data in bytes per second.
    /// </summary>
    public double AverageSpeedOfDataTransfer =>
        PacketCaptureDuration != TimeSpan.Zero
            ? TotalAmountOfBytesPassed / PacketCaptureDuration.TotalSeconds
            : TotalAmountOfBytesPassed;

    /// <summary>
    /// Gets the max number of packets per second.
    /// </summary>
    public long MaxNumberOfPackets =>
        Math.Max(Math.Max(_maxNumberOfPackets, _currentNumberOfPackets), (long)Math.Round(AverageNumberOfPackets));

    /// <summary>
    /// Gets the min number of packets per second.
    /// </summary>
    public long MinNumberOfPackets => Math.Min(_minNumberOfPackets, (long)Math.Round(AverageNumberOfPackets));

    /// <summary>
    /// Gets the max payload data in bytes per second.
    /// </summary>
    public long MaxSpeedOfDataTransfer =>
        Math.Max(Math.Max(_maxSpeedOfDataTransfer, _currentSizeOfPackets), (long)Math.Round(AverageSpeedOfDataTransfer));

    /// <summary>
    /// Gets the min payload data in bytes per second.
    /// </summary>
    public long MinSpeedOfDataTransfer => Math.Min(_minSpeedOfDataTransfer, (long)Math.Round(AverageSpeedOfDataTransfer));

    /// <summary>
    /// Gets or sets the total number of packets.
    /// </summary>
    private long TotalNumberOfPackets { get; set; }

    /// <summary>
    /// Gets or sets the total size of each packet's payload in bytes.
    /// </summary>
    private long TotalAmountOfBytesPassed { get; set; }

    private TimeSpan PacketCaptureDuration =>
        _earliestPacketTime == DateTime.MaxValue
            ? TimeSpan.Zero
            : _latestPacketTime - _earliestPacketTime;

    /// <inheritdoc />
    public void Process(CapturedPacket packet)
    {
        if (packet?.CapturedDateTime is null)
        {
            return;
        }

        var packetBytes = packet.OriginalPacketLength;

        TotalNumberOfPackets++;
        TotalAmountOfBytesPassed += packetBytes;

        if (packet.CapturedDateTime.Value < _earliestPacketTime)
        {
            _earliestPacketTime = packet.CapturedDateTime.Value;
        }

        if (packet.CapturedDateTime.Value > _latestPacketTime)
        {
            _latestPacketTime = packet.CapturedDateTime.Value;
        }

        var packetTimestampSeconds = packet.CapturedDateTime.Value.TruncateToSeconds();

        // Let's initialize currentTimestampSecond with first packet, if it is not initialized already.
        if (_currentTimestampSecond == DateTime.MaxValue)
        {
            _currentTimestampSecond = packetTimestampSeconds;
        }

        if (_currentTimestampSecond != packetTimestampSeconds)
        {
            _maxNumberOfPackets = Math.Max(_maxNumberOfPackets, _currentNumberOfPackets);
            _maxSpeedOfDataTransfer = Math.Max(_maxSpeedOfDataTransfer, _currentSizeOfPackets);

            // If there is gap between time stamps, this means values for this gap time is zero.
            // This causes minimum values to be zero.
            if ((packetTimestampSeconds - _currentTimestampSecond).TotalSeconds > 1)
            {
                _minSpeedOfDataTransfer = 0;
                _minNumberOfPackets = 0;
            }

            // The first time slot will be a partial time slot, that is it will not be a full second slot.
            // The calculated Min values in this partial slot will not be exact.
            // Therefore, the values in this partial slot are excluded from the Min calculation.
            // There is a partial end slot and it's values are also excluded from the Min calculation.
            if (_partialStartSlotSkipped)
            {
                _minSpeedOfDataTransfer = Math.Min(_minSpeedOfDataTransfer, _currentSizeOfPackets);
                _minNumberOfPackets = Math.Min(_minNumberOfPackets, _currentNumberOfPackets);
            }

            _partialStartSlotSkipped = true;
            _currentTimestampSecond = packetTimestampSeconds;
            _currentNumberOfPackets = 0;
            _currentSizeOfPackets = 0;
        }

        _currentNumberOfPackets++;
        _currentSizeOfPackets += packetBytes;
    }
}
