# Network Topology Mapper (NTM) v1.0.0

**Network Topology Mapper (NTM)** là công cụ dòng lệnh (CLI) mã nguồn mở viết bằng **C++20**, được thiết kế để khám phá thiết bị trong mạng LAN (Host Discovery), thu thập thông tin đa tầng (L2/L3/L4, Reverse DNS, IEEE OUI Vendor) và suy luận sơ đồ kết nối mạng dựa trên bằng chứng (**Evidence-Based Topology Inference**).

---

## 1. Giới thiệu dự án

Khác với các công cụ ping sweep thông thường vốn chỉ liệt kê IP hoặc tự suy diễn các đường nối vật lý giả định, **NTM** tách biệt rõ ràng hai pha:

1. **Host Discovery Engine**: Khám phá thiết bị qua Layer-2 ARP (`AF_PACKET`), Layer-3 ICMP Echo (`SOCK_RAW` / `IPPROTO_ICMP`), Layer-4 Non-blocking TCP Connect Probe, kết hợp bảng láng giềng của kernel (`/proc/net/arp`), Reverse DNS (`getnameinfo`) và cơ sở dữ liệu MAC OUI cục bộ (hỗ trợ prefix 24-bit MA-L, 28-bit MA-M và 36-bit MA-S).
2. **Network Topology Engine**: Xây dựng đồ thị `TopologyGraph` sử dụng danh sách kề (Adjacency List), phân loại chặt chẽ từng liên kết thành:
   - **Observed Link**: Quan hệ được xác minh trực tiếp từ dữ liệu giao thức tầng liên kết (ví dụ: nhận trực tiếp gói tin Layer-2 ARP Reply trên broadcast domain của interface).
   - **Inferred Link**: Quan hệ được suy luận có cơ sở từ bảng định tuyến hệ điều hành (`/proc/net/route`), bảng ARP cache của kernel (`/proc/net/arp`) kết hợp phản hồi L3/L4.
   - **Unknown Relationship**: Chưa đủ dữ liệu giao thức để kết luận đường kết nối (tuyệt đối không được vẽ thành kết nối vật lý đã xác minh).

---

## 2. Mục tiêu và phạm vi

- Tự động phát hiện và phân loại các network interface trên máy chủ đang chạy (`Physical`, `Loopback`, `VPN`, `Bridge`, `Virtual/Docker`).
- Kiểm soát nghiêm ngặt phạm vi quét (`ScopeValidator`) trước khi khởi chạy worker: chặn loopback, multicast, broadcast, địa chỉ ngoài subnet được cấp phép và giới hạn tài nguyên.
- Hỗ trợ chạy đầy đủ đặc quyền Layer-2/Layer-3 với Linux Capabilities (`CAP_NET_RAW`) và tự động chuyển sang chế độ fallback an toàn (TCP Connect Probe + OS ARP Cache) khi chạy dưới quyền user thông thường.
- Hiển thị bảng kết quả trực quan trên terminal, đồng thời xuất dữ liệu sang **JSON** (có `schema_version`) và **Graphviz DOT** để kết xuất thành ảnh PNG/SVG.

---

## 3. Kiến trúc tổng thể

```
+-----------------------------------------------------------------------+
|                              CLI Parser                               |
|   (--interfaces, --interface, --auto, --target, --methods, --dry-run) |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                   InterfaceDiscovery & ScopeValidator                 |
|  - Linux: getifaddrs(), ioctl(), /proc/net/route, /sys/class/net      |
|  - Scope check: RFC1918/Lab subnet check, block loopback/multicast    |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                        DiscoveryCoordinator                           |
|  - ThreadPool (bounded workers & bounded task queue)                  |
|  - RateLimiter (token interval + max concurrent probes semaphore)     |
|  +-----------------+  +------------------+  +----------------------+  |
|  | ArpDiscovery    |  | IcmpDiscovery    |  | TcpConnectProbe      |  |
|  | (AF_PACKET L2)  |  | (RFC1071 L3 RTT) |  | (Non-blocking L4)    |  |
|  +-----------------+  +------------------+  +----------------------+  |
|  +-----------------------------------------------------------------+  |
|  | OsArpCacheReader (/proc/net/arp) + ReverseDnsResolver + OUI     |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                       TopologyInferenceEngine                         |
|  - Multi-factor Host Classification (Local, Gateway, LAN, Reachable)  |
|  - Evidence-Based Link Builder (Observed vs Inferred vs Unknown)      |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                         Export & Visualization                        |
|  - TerminalRenderer (ASCII Table)                                     |
|  - JsonExporter (nlohmann/json, schema v1.0.0)                        |
|  - DotExporter (Graphviz DOT -> PNG/SVG)                              |
+-----------------------------------------------------------------------+
```

---

## 4. Sơ đồ luồng hoạt động

1. **Parse CLI**: Kiểm tra tính hợp lệ của tham số dòng lệnh (`CliParser`).
2. **Khám phá Interface**: Thu thập danh sách interface qua `InterfaceDiscovery::discover_interfaces()`. Loại bỏ mặc định chọn mù quáng interface đầu tiên; lọc các interface LAN hợp lệ hoặc yêu cầu người dùng chỉ định khi có nhiều interface.
3. **Kiểm tra Scope (`ScopeValidator`)**: Xác thực toàn bộ danh sách IP mục tiêu nằm trong subnet được cấp phép và không vượt quá giới hạn tài nguyên (`max_targets = 1024`). Nếu bật `--dry-run`, in báo cáo kiểm tra và thoát an toàn.
4. **Kiểm tra quyền & Khởi tạo Probes**: Kiểm tra quyền mở `AF_PACKET` (ARP) và `SOCK_RAW` (ICMP). Nếu thiếu `CAP_NET_RAW`, cảnh báo rõ ràng và tiếp tục bằng `TcpConnectProbe` + `/proc/net/arp`.
5. **Thực thi Discovery song song**: Đẩy các tác vụ thăm dò vào `ThreadPool`, điều tiết tốc độ gửi gói và số lượng kết nối đồng thời qua `RateLimiter`.
6. **Làm giàu dữ liệu**: Tra cứu Reverse DNS (`getnameinfo`) và tên nhà sản xuất phần cứng từ MAC (`OuiLookup` hỗ trợ 24/28/36-bit prefix).
7. **Suy luận Topology (`TopologyInferenceEngine`)**: Phân loại thiết bị kèm lý do (`classification_reasons`) và tạo các cạnh `NetworkLink` có gắn nguồn bằng chứng và điểm tin cậy (`confidence_score`).
8. **Xuất kết quả**: Hiển thị bảng trên terminal và ghi file JSON / Graphviz DOT.

---

## 5. Cấu trúc thư mục

```text
NetworkTopologyMapper/
├── CMakeLists.txt
├── README.md
├── data/
│   └── oui.csv
├── docs/
│   └── ARCHITECTURE.md
├── include/
│   └── ntm/
│       ├── cli/
│       │   └── cli_parser.hpp
│       ├── discovery/
│       │   ├── discovery_engine.hpp
│       │   ├── oui_lookup.hpp
│       │   └── packet_headers.hpp
│       ├── export/
│       │   └── exporter.hpp
│       ├── net/
│       │   ├── interface_discovery.hpp
│       │   ├── ip_address.hpp
│       │   └── scope_validator.hpp
│       ├── topology/
│       │   ├── topology_inference.hpp
│       │   └── topology_model.hpp
│       └── utils/
│           ├── logger.hpp
│           ├── rate_limiter.hpp
│           └── thread_pool.hpp
├── src/
│   ├── main.cpp
│   ├── cli/
│   │   └── cli_parser.cpp
│   ├── discovery/
│   │   ├── discovery_engine.cpp
│   │   ├── oui_lookup.cpp
│   │   └── packet_headers.cpp
│   ├── export/
│   │   └── exporter.cpp
│   ├── net/
│   │   ├── interface_discovery.cpp
│   │   ├── ip_address.cpp
│   │   └── scope_validator.cpp
│   ├── topology/
│   │   ├── topology_inference.cpp
│   │   └── topology_model.cpp
│   └── utils/
│       ├── logger.cpp
│       ├── rate_limiter.cpp
│       └── thread_pool.cpp
└── tests/
    └── test_main.cpp
```

---

## 6. Công nghệ sử dụng

- **Ngôn ngữ**: C++20 (`std::jthread` / `std::thread`, `std::chrono::steady_clock`, `std::optional`, `std::string_view`, RAII).
- **Hệ thống Build**: CMake (>= 3.16).
- **Hạ tầng mạng Linux**: POSIX Socket API (`AF_PACKET`, `AF_INET`, `SOCK_RAW`, `SOCK_STREAM` non-blocking `poll()`, `getifaddrs()`, `ioctl()`, `/proc/net/route`, `/proc/net/arp`, `/sys/class/net`).
- **Tương thích kiểm thử Windows**: Winsock2 & IP Helper API (`GetAdaptersAddresses`) cho phép biên dịch và chạy toàn bộ bộ unit test cũng như TCP probe trên Windows.

---

## 7. Dependency cần cài đặt

| Dependency | Mục đích sử dụng |
|---|---|
| `cmake` (>= 3.16) | Quản lý cấu hình và biên dịch dự án |
| `g++` (>= 11) hoặc `clang++` (>= 14) | Trình biên dịch hỗ trợ C++20 |
| `nlohmann-json3-dev` | Đọc/ghi định dạng JSON (tự động tải qua CMake `FetchContent` nếu chưa cài trên hệ thống) |
| `libgtest-dev` | Framework GoogleTest cho Unit Testing (tự động tải qua `FetchContent` nếu chưa cài) |
| `graphviz` (`dot`) | Chuyển đổi file `.dot` sang ảnh sơ đồ `.png` / `.svg` |
| `libcap2-bin` (`setcap`) | Cấp quyền `CAP_NET_RAW` cho file thực thi trên Linux mà không cần chạy bằng `root` |

Trên **Debian 13 / Ubuntu 22.04+**:

```bash
sudo apt update
sudo apt install -y build-essential cmake nlohmann-json3-dev libgtest-dev graphviz libcap2-bin
```

---

## 8. Hướng dẫn build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Sau khi build thành công:
- File thực thi CLI: `./build/ntm`
- File thực thi Unit Test: `./build/ntm_tests`

---

## 9. Hướng dẫn chạy

```bash
# 1. Xem hướng dẫn sử dụng
./build/ntm --help

# 2. Liệt kê tất cả network interface trên máy
./build/ntm --interfaces

# 3. Kiểm tra phạm vi và mục tiêu (Dry-Run, không gửi gói tin)
./build/ntm --interface eth0 --target 192.168.2.0/24 --dry-run

# 4. Tự động khám phá subnet của interface eth0 và xuất JSON + DOT
./build/ntm --interface eth0 --auto --output-json result.json --output-dot topology.dot

# 5. Quét danh sách IP chỉ định với tốc độ và timeout tùy chỉnh
./build/ntm --interface eth0 --targets 192.168.2.1,192.168.2.10,192.168.2.20 \
            --methods arp,icmp,tcp --ports 22,80,443,8080 --threads 8 --rate 25 --timeout 1000
```

---

## 10. Quyền hạn Linux (`CAP_NET_RAW`)

- **ARP Discovery (`AF_PACKET`, `SOCK_RAW`)** và **ICMP Echo (`AF_INET`, `SOCK_RAW`)** yêu cầu quyền tạo raw socket.
- **TCP Connect Probe (`AF_INET`, `SOCK_STREAM`)** hoạt động hoàn toàn với quyền user thông thường.

Thay vì chạy toàn bộ chương trình dưới quyền `root` (`sudo`), hãy cấp riêng capability `CAP_NET_RAW` cho binary `ntm`:

```bash
sudo setcap cap_net_raw+ep ./build/ntm
getcap ./build/ntm
# Output: ./build/ntm = cap_net_raw+ep
```

Nếu chạy `./build/ntm` khi **không** có `CAP_NET_RAW`, chương trình sẽ tự động thông báo phương thức ARP/ICMP không khả dụng và tiếp tục quét bằng **TCP Connect Probe** kết hợp đọc `/proc/net/arp`.

---

## 11. Cách xuất JSON

```bash
./build/ntm --interface eth0 --auto --output-json result.json
```

File `result.json` bao gồm:
- `schema_version`: `"1.0.0"`
- `metadata`: Tên công cụ, phiên bản, thời gian UTC chuẩn ISO-8601.
- `scan_configuration`: Dải mục tiêu, các phương thức thực tế đã chạy, danh sách cảnh báo.
- `local_interface`: Cấu hình chi tiết của interface thực hiện quét.
- `hosts`: Danh sách tất cả các `HostNode` cùng `classification_reasons`, `discovery_methods`, `confidence_score`, `rtt_ms`.
- `links`: Danh sách các `NetworkLink` cùng `relation_status` (`Observed Link`, `Inferred Link`), `evidence_source`, `collection_method`, `confidence_level`.
- `scan_statistics`: Thống kê tổng số IP đã quét, số host phản hồi, số cạnh quan sát/suy luận và thời gian thực thi.

---

## 12. Cách xuất DOT và PNG

```bash
./build/ntm --interface eth0 --auto --output-dot topology.dot
dot -Tpng topology.dot -o topology.png
dot -Tsvg topology.dot -o topology.svg
```

Quy ước hiển thị trong sơ đồ Graphviz:
- **Local Host**: Hình `doubleoctagon` (màu xanh lá nhạt).
- **Default Gateway**: Hình `diamond` (màu vàng cam).
- **LAN Host**: Hình `box` bo góc (màu xanh dương nhạt).
- **Reachable Host (L3/L4 only)**: Hình `ellipse`.
- **Observed Link**: Đường liền nét đậm (`style="solid"`, màu xanh lá đậm) — xác minh trực tiếp qua Layer-2 ARP Reply.
- **Inferred Link**: Đường nét đứt (`style="dashed"`, màu xanh lam) — suy luận từ bảng định tuyến hoặc ARP cache + phản hồi L3/L4.
- **Unknown Relationship**: Không bao giờ được vẽ thành đường kết nối vật lý giả tạo.

---

## 13. Các giới hạn kỹ thuật (v1.0)

1. **Tầm nhìn Layer-2 Switch**: ARP, ICMP và TCP không cung cấp thông tin về các unmanaged/managed switch nằm giữa hai thiết bị. Do đó, v1.0 chỉ biểu diễn quan hệ thành viên trong cùng L2 Broadcast Domain hoặc L3 Default Gateway chứ không tự suy diễn cổng switch vật lý.
2. **Thiết bị chặn gói tin (Silent Hosts)**: Một thiết bị cấu hình tường lửa chặn ICMP và đóng toàn bộ cổng TCP nhưng nằm ngoài broadcast domain (hoặc chặn ARP) sẽ không phản hồi. NTM đánh dấu trạng thái `Unresponsive` thay vì khẳng định tuyệt đối thiết bị đã tắt nguồn.
3. **Giới hạn quy mô quét**: Để bảo vệ bộ nhớ và băng thông mạng LAN, mỗi lần quét giới hạn tối đa `1024` địa chỉ host (tương đương tối đa `/22`).

---

## 14. Hướng dẫn chạy Unit Test

Toàn bộ unit test được viết bằng **GoogleTest** và tách biệt hoàn toàn khỏi quyền raw socket:

```bash
ctest --test-dir build --output-on-failure
# Hoặc chạy trực tiếp binary test:
./build/ntm_tests
```

---

## 15. Lưu ý an toàn và phạm vi sử dụng

- Công cụ **NTM** chỉ được phép sử dụng trong phạm vi mạng nội bộ (LAN / Lab) mà bạn sở hữu hoặc được ủy quyền kiểm tra rõ ràng bằng văn bản.
- Module `ScopeValidator` được bật cứng để ngăn chặn việc quét ra địa chỉ Internet công cộng, loopback, multicast hoặc vượt qua default gateway sang các phân đoạn mạng chưa được khai báo.
