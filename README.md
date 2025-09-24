# Packet Capture Tools

This repository contains several tools to process packet captures for network analysis. The tools don't perform the packet capture itself, to perform packet captures use other tools such as `tcpdump` in linux or `pktmon` in windows, for example in windows:

```shell
pktmon stop
pktmon filter remove
pktmon start -c -f capture.etl
# capture in progress...
pktmon stop
pktmon etl2pcap capture.etl
```

## Requirements

- [dotnet](https://dotnet.microsoft.com/en-us/)

## How to build

Use `dotnet build` in the root directory of the repo to build the entire solution.

## Tools

- **Analyzer**: Packet Capture analyzer that can read [pcapng](https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap) files and perform network traffic analysis.

### Analyzer

The Analyzer contains logic for reading pcapng files and process captured packets to generate metrics and output a report based on the the captured network traffic.

The library is fully extensible, supporting different types of protocols and analysis which can be outputed in different report formats.

How to use:

- Import the library into a dotnet project
- Create a `SessionMetadata` object with the metadata of the capture, such as start and end time, and other environment information as needed. It is important to pass a valid `captureAddresses` parameter to this class. The `captureAddresses` is used to determine the transmission direction of packets, such as if a packet is generated from the host where the packet capture was performed or if a packet is incoming from the network to the host.
- Define an analysis configuration or use one of the existing ones (`DefaultTrafficAnalysisConfiguration`, `TdsTrafficAnalysisConfiguration`). The `IAnalysisConfiguration` interface defines the middlewares that are used to process packets, the analysis that will be performed and the sections that will be rendered in the report.
- Create an `AnalysisController` with the analysis configuration and the path/stream of the packet capture file(s).
- Execute the analysis (_this operation might take some seconds/minutes depending on the size of the packet capture file(s)_)
- Create a rendered (such as `TextRenderer` or `JsonRenderer`) to render the report based on the analysis. A report can be rendered in multiple formats.

Example code:

```cs
var sessionMetadata = new SessionMetadata(/* No Capture Addresses specified, the library will obtain the local machine interface addresses */);
using var analysisController = new AnalysisController(new DefaultTrafficAnalysisConfiguration(sessionMetadata), "capture.pcapng");
analysisController.Execute();

var renderer = new TextRenderer();

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine(analysisController.Report.Render(renderer).ToString());
```

Example output:

```plaintext
Packet Counters
---------------

[Global Packet Counters]
A Total breakdown of all captured packets metrics.

+---------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| Total Packets | TCP Packets | Resets | Retransmits | TCP Connections | TCP Sent | TCP Received | TCP Control % | TCP Data % |
+---------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+
| 1940722       | 1939695     | 302    | 189776      | 82              | 1.477 GB | 1.831 GB     | 1.36%         | 98.64%     |
+---------------+-------------+--------+-------------+-----------------+----------+--------------+---------------+------------+

[Packet Counters per protocol]
The percent and count of packets received / sent for each protocol.

[Network Layer]

+----------+---------+------------+----------+--------+
| Protocol | Count   | Percentage | Received | Sent   |
+----------+---------+------------+----------+--------+
| IPv4     | 1940503 | 100.00%    | 1148908  | 791595 |
| IPv6     | 0       | 0.00%      | 0        | 0      |
| ARP      | 23      | 0.00%      | 16       | 7      |
+----------+---------+------------+----------+--------+

[Transport Layer]

+----------+---------+------------+----------+--------+
| Protocol | Count   | Percentage | Received | Sent   |
+----------+---------+------------+----------+--------+
| TCP      | 1939695 | 99.96%     | 1148485  | 791210 |
| UDP      | 808     | 0.04%      | 423      | 385    |
+----------+---------+------------+----------+--------+

[Throughput]
The average, minimum and maximum number of packets and data transferred per second.

+-------------------+--------------+---------+--------------+
| Value             | Average      | Min     | Max          |
+-------------------+--------------+---------+--------------+
| Number of Packets | 66956.081 /s | 15 /s   | 287525 /s    |
| Speed             | 119.136 MB/s | 900 B/s | 542.848 MB/s |
+-------------------+--------------+---------+--------------+

[Per IP Packet Counters]
A Total breakdown of all captured packets metrics by IP address.

+-----------------+---------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| Dst IP          | Total Packets | TCP Packets | Resets (src, dst) | Retransmits | TCP Connections (New, Existing, Closed) | Average RTT(s) |
+-----------------+---------------+-------------+-------------------+-------------+-----------------------------------------+----------------+
| 10.0.0.1        | 309           | 309         | (0, 0)            | 31          | (1, 1, 0)                               | 0.003          |
| 10.0.0.2        | 45            | 45          | (0, 0)            | 13          | (2, 2, 0)                               | 0.005          |
| 10.0.0.3        | 22            | 22          | (0, 0)            | 6           | (1, 1, 0)                               | 0.004          |
| 10.0.0.4        | 10            | 10          | (0, 0)            | 1           | (1, 1, 0)                               | 0.116          |
| 10.0.0.5        | 1017839       | 1017839     | (64, 77)          | 187761      | (14, 14, 14)                            | 0.004          |
+-----------------+---------------+-------------+-------------------+-------------+-----------------------------------------+----------------+

[TCP Traffic Timings]
The percentiles of time for connection operations.

+---------------------+--------+--------+--------+--------+
| Timing              | 50th % | 90th % | 95th % | 99th % |
+---------------------+--------+--------+--------+--------+
| Connection Duration | 15 s   | 15.5 s | 15.5 s | 15.5 s |
| Handshake Duration  | 35 ms  | 131 ms | 188 ms | 282 ms |
| Between RST and SYN | _      | _      | _      | _      |
+---------------------+--------+--------+--------+--------+

TCP Resets
----------

[TCP Total Reset Analysis]
Graph showing TCP connection resets over the period of the packet capture operation.

   190┤             ╭╮
   180┤             ││
   170┤             ││
   160┤             ││
   150┤             ││
T  140┤             ││
C  130┤             ││
P  120┤             ││
   110┤             ││
R  100┤             ││
E   90┤             ││
S   80┤             ││                                            ╭╮
E   70┤             ││                                            ││
T   60┤             ││                                            ││
S   50┤             ││                                            ││
    40┤             ││                                            ││
    30┤             ││                                            ││
    20┤             ││                                            ││
    10┤             ││                                            ││
     0┤─ ─  ─  ─  ─ ╯╰  ─  ─ ─  ─  ─  ─  ─  ─  ─ ─  ─  ─  ─  ─  ─ ╯╰ ─  ─     ─  ─  ─  ─
       ----------------|---------------|---------------|---------------|---------------|-----
   09:30:48        09:30:53        09:30:59        09:31:04        09:31:10        09:31:16
                                TIME PERIOD OF DAY (HH:MM:SS)

```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
