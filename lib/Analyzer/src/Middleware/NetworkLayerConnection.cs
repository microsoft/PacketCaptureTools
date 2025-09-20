// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net;

namespace Microsoft.PacketCapture.Analyzer.Middleware;

/// <summary>
/// Network layer connection defined by source and destination IP addresses.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="NetworkLayerConnection" /> class.
/// </remarks>
/// <param name="sourceIpAddress">Source IP address.</param>
/// <param name="destinationIpAddress">Destination IP address.</param>
/// <exception cref="ArgumentNullException">Throws when sourceIpAddress or destinationIpAddress is null.</exception>
public class NetworkLayerConnection(IPAddress sourceIpAddress, IPAddress destinationIpAddress) : IEquatable<NetworkLayerConnection>
{

    /// <summary>
    /// Gets source IP address.
    /// </summary>
    public IPAddress SourceIpAddress { get; } = sourceIpAddress ?? throw new ArgumentNullException(nameof(sourceIpAddress));

    /// <summary>
    /// Gets destination IP address.
    /// </summary>
    public IPAddress DestinationIpAddress { get; } = destinationIpAddress ?? throw new ArgumentNullException(nameof(destinationIpAddress));

    /// <inheritdoc />
    public bool Equals(NetworkLayerConnection? connection) => IsSameConnection(connection, out _);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is NetworkLayerConnection connection && Equals(connection);

    /// <inheritdoc />
    public override int GetHashCode() =>
        SourceIpAddress.GetHashCode() <= DestinationIpAddress.GetHashCode()
            ? (SourceIpAddress, DestinationIpAddress).GetHashCode()
            : (DestinationIpAddress, SourceIpAddress).GetHashCode();

    /// <summary>
    /// Determines whether the specified <see cref="NetworkLayerConnection" /> is equal to the current <see cref="NetworkLayerConnection" />.
    /// </summary>
    /// <param name="other">The <see cref="NetworkLayerConnection" /> to compare with the current object.</param>
    /// <param name="hasSameDirection">Determines whether the specified <see cref="NetworkLayerConnection" /> is has the same direction as the current <see cref="NetworkLayerConnection" />.</param>
    /// <returns>true if the specified <see cref="NetworkLayerConnection" /> is equal to the current object; otherwise, false.</returns>
    public bool IsSameConnection(NetworkLayerConnection? other, out bool hasSameDirection)
    {
        hasSameDirection = false;

        if (other is null)
        {
            return false;
        }

        var sourceAndDestinationAreEqual = Equals(other.SourceIpAddress, SourceIpAddress) &&
                                           Equals(other.DestinationIpAddress, DestinationIpAddress);

        if (sourceAndDestinationAreEqual)
        {
            hasSameDirection = true;
            return true;
        }

        var sourceAndDestinationAreSwapped = Equals(other.SourceIpAddress, DestinationIpAddress) &&
                                             Equals(other.DestinationIpAddress, SourceIpAddress);

        return sourceAndDestinationAreSwapped;
    }
}
