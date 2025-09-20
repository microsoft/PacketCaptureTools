// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.PacketCapture.Analyzer.Packet.Application.Tds;

/// <summary>
/// TDS protocol message type.
/// </summary>
internal enum TdsMessageType
{
    /// <summary>
    /// SQL batch.
    /// </summary>
    SqlBatch = 0x1,

    /// <summary>
    /// Pre-TDS version 7 login.
    /// </summary>
    PreTds7Login = 0x2,

    /// <summary>
    /// RPC.
    /// </summary>
    Rpc = 0x3,

    /// <summary>
    /// Tabular result.
    /// </summary>
    TabularResult = 0x4,

    /// <summary>
    /// Server response.
    /// </summary>
    ServerResponse = 0x4,

    /// <summary>
    /// Attention signal (contains no data).
    /// </summary>
    AttentionSignal = 0x6,

    /// <summary>
    /// Bulk load data.
    /// </summary>
    BulkLoadData = 0x7,

    /// <summary>
    /// Federated authentication token.
    /// </summary>
    FedAuthToken = 0x8,

    /// <summary>
    /// Transaction manager request.
    /// </summary>
    TransactionManagerRequest = 0xE,

    /// <summary>
    /// TDS version 7 login.
    /// </summary>
    Tds7Login = 0x10,

    /// <summary>
    /// SSPI.
    /// </summary>
    SSPI = 0x11,

    /// <summary>
    /// Pre-login request.
    /// </summary>
    PreLogin = 0x12,
}
