#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../WebServer.h"

#include <chrono>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>

void WebServer::handleServerStats(
    SOCKET clientSocket
)
{
    const std::string command =
        "printf '__HOSTNAME__\\n'; "
        "hostname 2>/dev/null; "

        "printf '__OS__\\n'; "
        "grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null "
        "| cut -d= -f2- | tr -d '\\\"'; "

        "printf '__KERNEL__\\n'; "
        "uname -r 2>/dev/null; "

        "printf '__CPU__\\n'; "
        "grep -m1 'model name' /proc/cpuinfo 2>/dev/null "
        "| cut -d: -f2- | sed 's/^ *//'; "

        "printf '__CPUS__\\n'; "
        "nproc 2>/dev/null; "

        "printf '__CPUSTAT__\\n'; "
        "head -n 1 /proc/stat 2>/dev/null; "

        "printf '__LOAD__\\n'; "
        "awk '{print $1}' /proc/loadavg 2>/dev/null; "

        "printf '__MEM__\\n'; "
        "free -b 2>/dev/null "
        "| awk '/^Mem:/ {print $2\" \"$3\" \"$7}'; "

        "printf '__DISK__\\n'; "
        "df -B1 / 2>/dev/null "
        "| awk 'NR==2 {print $2\" \"$3\" \"$4}'; "

        "printf '__UPTIME__\\n'; "
        "awk '{print $1}' /proc/uptime 2>/dev/null; "

        "printf '__NETWORK__\\n'; "
        "cat /proc/net/dev 2>/dev/null "
        "| awk 'NR>2 {gsub(\":\", \"\", $1); "
        "$1 != \"lo\" {rx+=$2; tx+=$10}} "
        "END {print rx\" \"tx}'; "

        "printf '__PROCESSES__\\n'; "
        "ps -e --no-headers 2>/dev/null | wc -l";

    std::string output;

    if (
        !executeSshCommand(
            command,
            output
        )
        )
    {
        sendJson(
            clientSocket,
            500,
            "{\"error\":\"Failed to execute server statistics command\"}"
        );

        return;
    }

    std::map<std::string, std::string> values;

    std::istringstream stream(output);

    std::string line;
    std::string currentKey;

    while (std::getline(stream, line))
    {
        if (
            !line.empty() &&
            line.back() == '\r'
            )
        {
            line.pop_back();
        }

        if (
            line.size() > 4 &&
            line.front() == '_' &&
            line.back() == '_'
            )
        {
            currentKey = line;

            continue;
        }

        if (!currentKey.empty())
        {
            values[currentKey] = line;

            currentKey.clear();
        }
    }

    std::string hostname =
        values["__HOSTNAME__"];

    std::string os =
        values["__OS__"];

    std::string kernel =
        values["__KERNEL__"];

    std::string cpuModel =
        values["__CPU__"];

    std::string cpuCount =
        values["__CPUS__"];

    std::string cpuStat =
        values["__CPUSTAT__"];

    std::string load =
        values["__LOAD__"];

    std::string memory =
        values["__MEM__"];

    std::string disk =
        values["__DISK__"];

    std::string uptime =
        values["__UPTIME__"];

    std::string network =
        values["__NETWORK__"];

    std::string processes =
        values["__PROCESSES__"];

    unsigned long long cpuUser = 0;
    unsigned long long cpuNice = 0;
    unsigned long long cpuSystem = 0;
    unsigned long long cpuIdle = 0;
    unsigned long long cpuIowait = 0;
    unsigned long long cpuIrq = 0;
    unsigned long long cpuSoftIrq = 0;
    unsigned long long cpuSteal = 0;

    {
        std::istringstream cpuStream(cpuStat);

        std::string cpuName;

        cpuStream
            >> cpuName
            >> cpuUser
            >> cpuNice
            >> cpuSystem
            >> cpuIdle
            >> cpuIowait
            >> cpuIrq
            >> cpuSoftIrq
            >> cpuSteal;
    }

    unsigned long long cpuIdleTotal =
        cpuIdle + cpuIowait;

    unsigned long long cpuTotal =
        cpuUser +
        cpuNice +
        cpuSystem +
        cpuIdle +
        cpuIowait +
        cpuIrq +
        cpuSoftIrq +
        cpuSteal;

    double cpuPercent = 0.0;

    if (
        previousCpuTotal > 0 &&
        cpuTotal > previousCpuTotal &&
        cpuIdleTotal >= previousCpuIdle
        )
    {
        unsigned long long totalDelta =
            cpuTotal - previousCpuTotal;

        unsigned long long idleDelta =
            cpuIdleTotal - previousCpuIdle;

        if (totalDelta > 0)
        {
            cpuPercent =
                (
                    1.0 -
                    (
                        static_cast<double>(idleDelta) /
                        static_cast<double>(totalDelta)
                        )
                    ) * 100.0;
        }
    }

    previousCpuTotal = cpuTotal;
    previousCpuIdle = cpuIdleTotal;

    if (cpuPercent < 0.0)
        cpuPercent = 0.0;

    if (cpuPercent > 100.0)
        cpuPercent = 100.0;

    unsigned long long memTotal = 0;
    unsigned long long memUsed = 0;
    unsigned long long memAvailable = 0;

    {
        std::istringstream memStream(memory);

        memStream
            >> memTotal
            >> memUsed
            >> memAvailable;
    }

    double memoryPercent = 0.0;

    if (memTotal > 0)
    {
        memoryPercent =
            (
                1.0 -
                (
                    static_cast<double>(memAvailable) /
                    static_cast<double>(memTotal)
                    )
                ) * 100.0;
    }

    if (memoryPercent < 0.0)
        memoryPercent = 0.0;

    if (memoryPercent > 100.0)
        memoryPercent = 100.0;

    unsigned long long diskTotal = 0;
    unsigned long long diskUsed = 0;
    unsigned long long diskAvailable = 0;

    {
        std::istringstream diskStream(disk);

        diskStream
            >> diskTotal
            >> diskUsed
            >> diskAvailable;
    }

    double diskPercent = 0.0;

    if (diskTotal > 0)
    {
        diskPercent =
            (
                static_cast<double>(diskUsed) /
                static_cast<double>(diskTotal)
                ) * 100.0;
    }

    unsigned long long networkRx = 0;
    unsigned long long networkTx = 0;

    {
        std::istringstream networkStream(network);

        networkStream
            >> networkRx
            >> networkTx;
    }

    const auto now =
        std::chrono::steady_clock::now();

    const long long currentNetworkTimeMs =
        std::chrono::duration_cast<
        std::chrono::milliseconds
        >(
            now.time_since_epoch()
        ).count();

    double networkRxSpeed = 0.0;
    double networkTxSpeed = 0.0;

    if (
        previousNetworkTimeMs > 0 &&
        currentNetworkTimeMs > previousNetworkTimeMs &&
        networkRx >= previousNetworkRx &&
        networkTx >= previousNetworkTx
        )
    {
        const double seconds =
            static_cast<double>(
                currentNetworkTimeMs -
                previousNetworkTimeMs
                ) / 1000.0;

        if (seconds > 0.0)
        {
            networkRxSpeed =
                static_cast<double>(
                    networkRx -
                    previousNetworkRx
                    ) / seconds;

            networkTxSpeed =
                static_cast<double>(
                    networkTx -
                    previousNetworkTx
                    ) / seconds;
        }
    }

    previousNetworkRx = networkRx;
    previousNetworkTx = networkTx;
    previousNetworkTimeMs = currentNetworkTimeMs;

    std::ostringstream json;

    json
        << "{"

        << "\"connected\":true"

        << ",\"status\":\"online\""

        << ",\"hostname\":\""
        << jsonEscape(hostname)
        << "\""

        << ",\"name\":\""
        << jsonEscape(hostname)
        << "\""

        << ",\"os\":\""
        << jsonEscape(os)
        << "\""

        << ",\"kernel\":\""
        << jsonEscape(kernel)
        << "\""

        << ",\"cpu_model\":\""
        << jsonEscape(cpuModel)
        << "\""

        << ",\"cpu_count\":"
        << (
            cpuCount.empty()
            ? "0"
            : cpuCount
            )

        << ",\"cpu_percent\":"
        << std::fixed
        << std::setprecision(1)
        << cpuPercent

        << ",\"load1\":"
        << (
            load.empty()
            ? "0"
            : load
            )

        << ",\"memory_total\":"
        << memTotal

        << ",\"memory_used\":"
        << memUsed

        << ",\"memory_available\":"
        << memAvailable

        << ",\"memory_percent\":"
        << std::fixed
        << std::setprecision(1)
        << memoryPercent

        << ",\"disk_total\":"
        << diskTotal

        << ",\"disk_used\":"
        << diskUsed

        << ",\"disk_available\":"
        << diskAvailable

        << ",\"disk_percent\":"
        << std::fixed
        << std::setprecision(1)
        << diskPercent

        << ",\"uptime\":"
        << (
            uptime.empty()
            ? "0"
            : uptime
            )

        << ",\"network_rx\":"
        << networkRx

        << ",\"network_tx\":"
        << networkTx

        << ",\"network\":"
        << (networkRx + networkTx)

        << ",\"network_rx_speed\":"
        << std::fixed
        << std::setprecision(1)
        << networkRxSpeed

        << ",\"network_tx_speed\":"
        << std::fixed
        << std::setprecision(1)
        << networkTxSpeed

        << ",\"processes\":"
        << (
            processes.empty()
            ? "0"
            : processes
            )

        << "}";

    sendJson(
        clientSocket,
        200,
        json.str()
    );
}