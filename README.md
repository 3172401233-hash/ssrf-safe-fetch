# safereq — SSRF 安全的 HTTP/HTTPS 请求库

`safereq` 用 Python 3.11+ 标准库实现，供业务系统读取用户提交的外部链接。
它解决的核心问题是：**URL 检查通过后，实际 TCP 连接的地址必须仍然是被批准的
地址**，而不是只在请求前做一次域名/字符串过滤就把 URL 交给底层库重新解析。

无第三方依赖、无 Docker、无独立命令行工具，也不提供网页界面。

## 安装与要求

- Python 3.11 或更高版本（开发与验证环境为 3.14）。
- 仅使用标准库：`socket`、`ssl`、`ipaddress`、`urllib.parse`、`unittest` 等。
- 直接把 `safereq/` 目录放进项目，或将仓库根目录加入 `PYTHONPATH` 即可。

## 快速上手

```python
from safereq import SafeHttpClient

client = SafeHttpClient()
response = client.get("https://example.com/data")
print(response.status_code, response.body)
```

带白名单与自定义限制：

```python
from safereq import SafeHttpClient, Limits, Whitelist

client = SafeHttpClient(
    whitelist=Whitelist(
        domains=("api.partner.com",),
        ports=(443, 8443),
        networks=("8.8.8.0/24",),          # 可选，进一步收窄
    ),
    limits=Limits(
        connect_timeout=3.0,
        read_timeout=8.0,
        total_timeout=20.0,
        max_redirects=3,
        max_header_bytes=32 * 1024,
        max_body_bytes=1024 * 1024,
    ),
)
response = client.request(
    "POST",
    "https://api.partner.com/webhook",
    headers={"X-Request-Id": "abc"},
    body=b'{"event": 1}',
)
```

## API 概览

- `SafeHttpClient(whitelist=None, limits=None, resolver=None, connector=None,
  clock=None, allow_https_downgrade=False)`
  - `get(url, headers=None)` / `post(url, headers=None, body=None)` /
    `request(method, url, headers=None, body=None)`。
  - 返回 `Response`，字段包括 `status_code`、`reason`、`headers`、
    `raw_headers`、`body`、`target`、`peer`、`hop`、`extra`。
  - `response.extra["approved_addresses"]` 记录该跳实际批准的 IP 集合，
    便于审计。
- `Whitelist(domains=(), ports=(), networks=())`：空元组表示该维度不额外限制。
- `Limits(...)`：所有资源限制，见下文默认值。
- 解析器、连接器、时钟均可替换（实现对应 `Protocol` 即可），用于离线测试。

## 默认资源限制

| 限制 | 默认值 | 说明 |
| --- | --- | --- |
| `connect_timeout` | 5.0 秒 | 单次 TCP 建连超时，且不超过总时限剩余值 |
| `read_timeout` | 10.0 秒 | 两次 socket 读取之间的最大间隔 |
| `total_timeout` | 30.0 秒 | 整条重定向链的总时限，基于单调时钟 |
| `max_redirects` | 5 | 重定向跳数上限 |
| `max_header_bytes` | 64 KiB | 响应头累计字节上限 |
| `max_body_bytes` | 5 MiB | 响应正文累计字节上限 |

正文按**实际读取到的字节**累计：没有 `Content-Length`、声明值不准确、或使用
`Transfer-Encoding: chunked` 时限额同样生效。请求固定使用
`Accept-Encoding: identity`，遇到 `gzip`、`deflate` 等不支持的
`Content-Encoding` 直接抛出 `ResponseError`。

## URL 与主机规则

- 只接受 `http` 与 `https`，scheme 大小写不敏感但会归一化为小写。
- 拒绝用户名/密码（userinfo）、控制字符（含 NUL、CR、LF、TAB、DEL）、空白、
  反斜杠、URL fragment。
- 端口必须是纯数字且位于 1-65535；未指定时使用 80/443 默认端口。
- IPv4 仅接受规范的点分十进制，`0x7f000001`、十进制整数 `2130706433`、
  带前导零的 `0177.0.0.1` 等有歧义写法一律报错。
- IPv6 必须放在方括号内，拒绝裸 IPv6、未闭合括号、zone id（`%eth0`）。
- 回环、私有、链路本地、未指定、多播、保留地址默认全部拒绝。
- IPv4 映射的 IPv6（如 `::ffff:127.0.0.1`）会先还原成 IPv4 再分类，
  无法借映射形式绕过检查。

域名处理规则：

- **大小写**：域名按大小写不敏感处理，统一归一化为小写后再匹配与连接。
- **国际化域名（IDN）**：非 ASCII 标签使用 IDNA 编码为 A-label
  （例如 `bücher.example` → `xn--bcher-kva.example`），编码失败即拒绝。
  实现基于标准库的 `str.encode("idna")`（IDNA2003 体系），对 Unicode 版本
  敏感的边角字符（如部分历史映射、emoji 域名）行为随 Python 版本而定。
- **末尾点**：允许单个末尾点（FQDN 写法），解析后用 `trailing_dot` 标记；
  连续点、多个末尾点、空标签拒绝。匹配白名单时末尾点会被忽略。
- 地址判断**不使用字符串前缀**：`localhost.evil.example` 只是普通域名，
  不会因为包含 `localhost` 字样被当成本机；是否本机完全取决于解析后的 IP 分类。

## DNS 检查如何与实际连接绑定

每一跳都执行完整流水线，这是本库防 SSRF 的关键：

1. 严格解析 URL，得到 `Target`（scheme、主机、端口、路径）。
2. 应用主机名/端口白名单策略。
3. 调用解析器**一次性**取得该主机的全部地址（默认基于 `getaddrinfo`，去重）。
4. 对解析结果中的**每一个地址**做公网分类与网络白名单检查；只要有一个地址
   不符合策略，整次请求立即拒绝，不会“挑一个能用的”。
5. 把通过检查的地址集合原样交给连接器。连接器直接以 IP 字面量调用
   `socket.connect`，**不再进行第二次 DNS 解析**，因此 DNS rebinding 无法在
   检查与连接之间插入新地址。
6. TCP 建连后，连接器从内核读取 `getpeername()`，规范化后核对它是否属于本次
   批准集合；不在集合内立即关闭并抛出 `PeerMismatchError`。
7. HTTPS 即使 TCP 目标是 IP，TLS 的 SNI（`server_hostname`）与证书主机名校验
   仍使用**原始域名**。默认 `SSLContext` 强制 `check_hostname=True`、
   `verify_mode=CERT_REQUIRED`、TLS 1.2+，不提供关闭验证的开关；传入不安全的
   context 会被拒绝。
8. `Host` 头由库根据目标自动生成（默认端口省略、IPv6 带方括号），调用方
   无法覆盖；`Connection`、`Accept-Encoding`、`Content-Length`、
   `Transfer-Encoding` 等也由库管理。

## 白名单语义

- 白名单只能**收窄**可达范围，永远不能放行非公网地址。即使把
  `127.0.0.0/8` 加进网络白名单，回环地址仍因分类策略被拒绝。
- 域名匹配带边界检查：`allowed.example` 匹配自身与 `a.allowed.example`，
  但绝不匹配 `allowed.example.evil` 或 `notallowed.example`。
- 端口白名单与网络白名单独立生效，任一不满足即拒绝。

## 重定向策略

- 对 301/302/303/307/308 逐跳处理，支持相对 `Location`（基于当前跳 URL 用
  `urljoin` 解析）。
- 每一跳都重新执行 URL 解析、DNS、地址分类、连接对端校验；新域名意味着一次
  全新的完整检查。
- 默认禁止 HTTPS 降级到 HTTP（构造客户端时显式传
  `allow_https_downgrade=True` 才允许，通常不建议）。
- 检测循环跳转（scheme+主机+端口+路径完全相同）；缺少 `Location`、或出现
  多个含糊的 `Location` 头都抛出 `RedirectError`。
- 307/308 保留原方法与请求体；301/302/303 按常规改为 GET 并丢弃请求体。
- 跨主机（主机、端口或 scheme 变化）重定向时，自动剥离 `Authorization`、
  `Cookie`、`Proxy-Authorization`，也不转发逐跳头；同主机则保留普通业务头。
- 库本身不维护 Cookie 罐，不会自动携带或回写任何 Cookie。

## 代理与敏感信息

- 基于原始 socket 实现，**完全不读取** `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
  等环境变量，也不实现任何代理协商；请求始终直连批准的 IP。
- 不自动转发 Cookie、Authorization 等敏感头（见上）。
- 凭据在 URL 解析阶段就被拒绝，异常消息只包含主机、地址、跳数等定位信息，
  不会回显带 userinfo 的完整 URL。

## 异常体系

所有异常都继承 `SafeRequestError`，可按失败阶段精确捕获：

| 异常 | 触发阶段 |
| --- | --- |
| `URLError` / `HeaderError` / `RequestConfigError` | URL、请求头或入参不合法 |
| `PolicyError` | 主机/端口/地址被策略拒绝（含 `reason`、`host`、`address`、`hop`） |
| `DNSResolutionError` | DNS 失败或无可用地址 |
| `ConnectionFailedError` / `PeerMismatchError` | TCP 建连失败、对端不在批准集合 |
| `TLSError` | TLS 握手或证书验证失败 |
| `RedirectError` | 重定向响应非法、循环、降级等 |
| `LimitExceeded` | 超时、跳数、响应头/正文超限（含 `reason`、`limit`、`observed`） |
| `ReadError` / `ResponseError` | 连接读取中断、响应格式或内容编码不支持 |

无论请求成功、被策略拒绝、超限还是读取出错，连接都会被关闭（`close()`
幂等并吞掉关闭时的传输错误）。

## 可替换组件（便于测试）

- `Resolver`：`resolve(target) -> list[ResolvedAddress]`，默认 `SystemResolver`。
- `Connector`：`connect(target, approved, timeout, hop) -> SafeConnection`，
  默认 `DefaultConnector`。
- `Clock`：`now() -> float`，默认 `MonotonicClock`（`time.monotonic`）。

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

测试全部离线运行，不访问真实网站或公共 DNS：

- DNS 用脚本化的假解析器模拟，可构造公网/私网混合结果、解析结果变化等场景。
- TCP 使用本机 loopback 上的临时服务器与 `socket.socketpair`，覆盖分片响应、
  chunked、读超时、连接释放等真实 socket 行为。
- TLS 分支通过注入可记录参数的 `SSLContext` 工厂验证 SNI 与证书校验配置，
  不发起真实 TLS 握手。

## 支持平台与已知边界

- 支持任何提供标准 `socket`/`ssl`/`ipaddress` 的 CPython 3.11+ 平台。
- IP 分类依赖标准库 `ipaddress` 的标志位；不同 Python 版本对文档保留网段
  （如 TEST-NET、基准地址）的 `is_global`/`is_private` 判定可能不同，测试
  使用确定的公网地址以避免版本差异。
- IDNA 使用标准库 IDNA2003 编码，未实现 UTS #46 的全部规范化（如全角/兼容
  字符映射）；强需求场景应在上层先做规范化。
- 仅实现 HTTP/1.1，不支持 HTTP/2、HTTP/3、明文压缩传输编码、响应体自动解码。
- 不处理需要客户端证书、mTLS、代理认证或 WebSocket 的场景。
- 不做 DNS-over-HTTPS/TLS；解析阶段的网络可见性取决于运行环境的系统解析器。

## 重要安全说明

本库能阻止应用把请求发往非公网地址、缓解 DNS rebinding 与重定向绕过，但
**不能替代网络出口隔离**。容器/主机防火墙、安全组、独立出口网段、最小权限的
网络命名空间等纵深防御仍然必要：例如主机本地仍可能存在攻击者可控的公网形态
服务、云环境元数据端点的访问控制、以及应用自身的业务级越权，都不是单靠 URL
抓取库可以覆盖的。建议把本库与出口白名单/网络策略结合使用。
