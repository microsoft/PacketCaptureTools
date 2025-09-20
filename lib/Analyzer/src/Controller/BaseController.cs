// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.PacketCapture.Analyzer.Controller.Configuration;
using Microsoft.PacketCapture.Analyzer.Report;
using Microsoft.PacketCapture.Analyzer.Router;
using System;
using System.Threading;

namespace Microsoft.PacketCapture.Analyzer.Controller;

/// <summary>
/// Base class for the packet capture analysis library controller.
/// </summary>
public abstract class BaseController : IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BaseController" /> class.
    /// </summary>
    /// <param name="configuration">The analysis configuration.</param>
    protected BaseController(IAnalysisConfiguration configuration)
    {
        _ = configuration ?? throw new ArgumentNullException(nameof(configuration));

        Report = configuration.Report;
        PacketRouter = new PacketRouter(configuration);
    }

    /// <summary>
    /// Gets the report.
    /// </summary>
    public IReport Report { get; }

    /// <summary>
    /// Gets the packet router which is for directing packets and connections to the correct analyses.
    /// </summary>
    internal PacketRouter PacketRouter { get; }

    /// <inheritdoc />
    public abstract void Dispose();

    /// <summary>
    /// Execute analysis.
    /// </summary>
    /// <param name="cancellationToken">Optional. Cancellation token to stop analysis execution.</param>
    public abstract void Execute(CancellationToken cancellationToken = default);
}