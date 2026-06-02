# 系统架构设计

## 目标

本阶段完成“业务逻辑”到“密码学核心”的映射，并在阶段二开始接入真实 pairing 后端。系统按课程 PoC 定位设计，强调概念完整、边界清晰、便于答辩演示和后续扩展。

核心能力是企业员工在客户端加密文件后上传到文件服务。文件服务只能保存密文和元数据，无法解密内容。默认业务路径采用 BF-IBE Dent/FO KEM + AES-256-GCM DEM：文件正文只用 AES-GCM 加密一次，每个接收者有自己的 KEM key envelope。

系统同时保留 Boneh-Franklin 论文 direct IBE 算法作为实验对比：

- `BasicIdent`: 论文 Section 4.1 的基础 IBE，安全目标为 IND-ID-CPA。
- `FullIdent`: 论文 Section 4.2 中经 Fujisaki-Okamoto 转换后的完整 IBE，安全目标为 IND-ID-CCA。

业务主路径不直接用 IBE 加密大文件 chunk，而是按协议把 BF-IBE 改造成 Dent/FO KEM。KEM 密文为 `C_KEM=(U,V)`，其中 `U=rP` 是真实 G1 曲线点；DEM 使用 AES-256-GCM 加密文件正文。当前可运行后端使用 BLS12-381 的 Type-3 pairing：`Q_ID` 和 `d_ID` 在 G2，`Ppub` 和 `U=rP` 在 G1，配对函数为 `py_ecc.optimized_bls12_381.pairing(Q_G2, P_G1)`，即 optimal Ate pairing。

## 核心实体

### PKG 企业密钥中心

PKG 是唯一持有 `MasterSecret` 的服务，负责：

- 初始化和发布 `PublicParameters`。
- 校验模拟 SSO JWT，确认员工处于 active 状态。
- 按客户端请求的小时或时间段，派生 `email||YYYY-MM-DD-HH` 对应的用户私钥。
- 发放私钥前校验员工是否仍为公司合法员工；离职、禁用或 JWT 无效时拒绝。
- 记录私钥发放审计事件。

PKG 不保存业务文件，也不接触文件明文。它只根据 `MasterSecret` 和时间绑定身份派生用户小时私钥。

### 文件服务 / 密文仓库

文件服务负责密文生命周期管理：

- 接收客户端上传的 AES-GCM 密文文件和 `HybridEncryptedFileHeader`。
- 保存文件元数据、接收者列表、密文哈希和审计事件。
- 根据 JWT、员工 active 状态、owner/recipient 关系限制文件列表、元数据读取和下载。
- 不持有 `MasterSecret`、用户小时私钥或文件明文。

阶段一默认使用本地磁盘模拟密文对象存储，后续可以替换为 NAS 或对象存储。

### 员工客户端 CLI

客户端是唯一接触明文文件的组件，负责：

- 使用模拟 SSO 登录获得 JWT。
- 从 PKG 获取公共参数，并按文件 header 中的小时申请解密私钥。
- 生成随机 `file_key` 并用 AES-256-GCM 加密文件正文。
- 为每个接收者生成 BF-IBE Dent/FO KEM 密文 `(U,V)`，并用 KEM key 封装同一个 `file_key`。
- 保留 `BasicIdent` 与 `FullIdent` direct IBE 模式，用于 CPA/CCA 性能对比。
- 上传密文和加密头到文件服务。
- 下载密文后，按 header 中的 `time_bound_id` 申请对应小时私钥并尝试解密。

客户端不持久化私钥；私钥只在当前会话缓存中使用，避免离职前长期保存大量历史或未来私钥。

## 时间绑定身份

系统固定使用以下格式作为 IBE 公钥身份：

```text
email||YYYY-MM-DD-HH
```

示例：

```text
alice@company.com||2026-05-17-14
```

规则：

- `email` 统一转为小写并去除首尾空格。
- `YYYY-MM-DD-HH` 表示 UTC 小时。
- PKG 服务端时间是员工状态校验和审计的权威来源。
- 客户端可以请求任意 `YYYY-MM-DD-HH` 小时，PKG 记录请求小时、发放时间和员工状态。
- 所有节点应使用统一 NTP 源同步时间。

## 密钥分发策略

采用客户端 Pull：

1. 客户端下载文件 header，读取需要解密的 `time_bound_id` 或 `encryption_hour`。
2. 客户端携带 JWT 请求 `POST /pkg/private-keys/request`，提交一个小时或一段小时列表。
3. PKG 校验 JWT 和员工状态，确认员工仍为 active。
4. 若员工合法，PKG 按请求小时构造 `email||YYYY-MM-DD-HH`。
5. PKG 从 `MasterSecret` 派生对应小时私钥，返回一个或多个 `KeyPackage`。
6. 客户端只在当前会话中缓存私钥，用完后清理。

该策略的安全边界是“访问时员工是否合法”。只要员工仍在职，他可以下载自己有权访问的密文，并申请任意时间段私钥来访问旧文件；一旦离职或禁用，文件服务停止提供列表/下载，PKG 也停止发放任何小时的私钥。

## 加密数据流

1. 客户端获取公共参数。
2. 客户端生成 256-bit `file_key`，用 AES-256-GCM 加密文件正文一次。
3. 客户端为每个接收者和文件加密小时构造 `TimeBoundIdentity`。
4. 对每个接收者运行 `KEM_Encap`：生成 `sigma`，计算 `r=H3(sigma)`、`U=rP`、`V=sigma xor H2(e(Q_ID,Ppub)^r)`、`K=H4(sigma)`。
5. 客户端用接收者的 `K` 通过 AES-GCM 封装同一个 `file_key`，生成 `RecipientKeyEnvelope`。
6. 客户端上传一份 DEM 密文文件和 `HybridEncryptedFileHeader`。

## 解密数据流

1. 接收者客户端向文件服务请求密文文件和 `HybridEncryptedFileHeader`。
2. 文件服务校验 JWT、员工 active 状态，并确认用户是 owner 或 recipient。
3. 通过后，客户端下载密文并从 header 中读取自己的 `time_bound_id`。
4. 客户端向 PKG 申请该小时私钥；PKG 再次校验员工 active 状态。
5. 客户端在 header 中查找自己的 `RecipientKeyEnvelope`，并校验其 `time_bound_id` 与申请到的私钥一致。
6. 客户端运行 `KEM_Decap`：恢复 `sigma'`，重算 `r'=H3(sigma')`，严格检查 `U == r'P`。
7. KEM 校验通过后解开 `file_key`，再用 AES-256-GCM 解密正文；任何 KEM/DEM 失败都对外统一为 `REJECT`。

## 任意时间私钥申请

系统不再给文件设置访问有效期。文件加密时通常使用发送时所在小时作为身份，例如：

```text
alice@company.com||2026-05-17-02
```

如果 Alice 在 08:00 访问 02:00 收到的文件，客户端读取 header 中的 `2026-05-17-02`，再向 PKG 申请 02 点私钥。PKG 不判断这个小时是否已经过去，只判断 Alice 当前是否仍是公司合法员工。

申请时间段时，客户端可以一次提交多个小时：

```text
2026-05-17-02
2026-05-17-03
2026-05-17-04
```

如果员工已离职、禁用或 JWT 失效，文件服务会先拒绝列表、元数据读取和下载；即便绕过文件服务拿到旧密文，PKG 也会拒绝所有小时的私钥申请。因此旧文件能否访问取决于“访问时是否仍是合法员工”，而不是文件发送时间是否过期。

## BasicIdent 与 FullIdent 性能实验

阶段二的实验目标是比较“获得 CCA 安全”相对 CPA 基线的开销，而不是证明 CCA 比 CPA 更快。

- BasicIdent 加密密文为 `<U, V>`，其中 `U` 序列化为 96 字节 BLS12-381 G1 点；解密主要成本是一次 pairing 和一次 `H2` 掩码恢复。
- FullIdent 加密密文为 `<U, V, W>`，增加 `H3`、`H4`、随机 `sigma` 和消息绑定。
- FullIdent 解密除了 pairing，还需要恢复 `sigma`、恢复消息、重新计算 `r = H3(sigma, M)`，并检查 `U = rP`。
- 对大文件直接 IBE 加密时，单个文件的成本随 `接收者数量 × chunk 数量` 线性增长；批量处理多个文件或多个请求小时会继续线性增加。

建议指标：

- `setup_ms`: 系统参数生成时间。
- `extract_ms`: 每个用户小时私钥派生时间。
- `encrypt_ms`: 单 chunk、单接收者、单小时加密时间。
- `decrypt_ms`: 单 chunk 解密时间。
- `ciphertext_expansion`: BasicIdent `<U,V>` 与 FullIdent `<U,V,W>` 的密文膨胀。
- `tamper_reject_ms`: FullIdent 篡改密文拒绝耗时。

## KEM/DEM 业务安全策略

- KEM 层使用 Dent/FO 去随机化和重加密校验，业务密文不包含 FullIdent 的 `W` 分量。
- DEM 层使用 AES-256-GCM，文件正文、封装的 `file_key` 都具备认证校验。
- 多接收者文件只保存一份 DEM 密文；每个接收者各自保存一个 KEM key envelope。
- 客户端和服务层对 KEM 校验失败、key unwrap 失败、DEM tag 失败统一返回 `REJECT`，避免报错预言机。

## 威胁边界

本阶段明确以下边界：

- 文件服务泄露：攻击者只能获得密文、加密头和元数据，不能直接解密文件。
- 员工离职或禁用：文件服务拒绝下载，PKG 不再为该员工发放任何小时或时间段的私钥。
- 密文篡改：业务路径通过 KEM 重加密校验和 AES-GCM tag 拦截；BasicIdent 仅作为 CPA 基线用于对比。
- 时钟漂移：PKG 时间为准，客户端时间只用于审计和偏差提示。

本阶段暂不覆盖生产级 HSM、密钥分片、灾备、多 PKG 高可用、真实 SSO 对接和零信任网络策略。
