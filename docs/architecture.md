# 阶段一系统架构设计

## 目标

本阶段完成“业务逻辑”到“密码学核心”的映射，不实现真实 BF-IBE 算法。系统按课程 PoC 定位设计，强调概念完整、边界清晰、便于答辩演示和后续阶段二开发。

核心能力是企业员工在客户端加密文件后上传到文件服务。文件服务只能保存密文和元数据，无法解密内容。接收者客户端在当前小时向 PKG 拉取自己的 BF-IBE 私钥，并用该私钥直接解密匹配当前小时的 IBE 密文块。

根据 Boneh-Franklin 论文，阶段二直接实现两个论文算法并做实验对比：

- `BasicIdent`: 论文 Section 4.1 的基础 IBE，安全目标为 IND-ID-CPA。
- `FullIdent`: 论文 Section 4.2 中经 Fujisaki-Okamoto 转换后的完整 IBE，安全目标为 IND-ID-CCA。

论文算法的消息空间是定长 `M ∈ {0,1}^n`。因此直接加密文件时，客户端需要把文件切成固定大小 chunk，每个 chunk 都生成一个 BasicIdent 或 FullIdent 密文。该设计牺牲大文件效率，但能清晰比较 CPA 与 CCA 安全模式的计算代价。

## 核心实体

### PKG 企业密钥中心

PKG 是唯一持有 `MasterSecret` 的服务，负责：

- 初始化和发布 `PublicParameters`。
- 校验模拟 SSO JWT，确认员工处于 active 状态。
- 以服务端当前小时为准，派生 `email||YYYY-MM-DD-HH` 对应的用户私钥。
- 记录私钥发放审计事件。

PKG 不保存业务文件，也不接触文件明文。它只根据 `MasterSecret` 和时间绑定身份派生用户小时私钥。

### 文件服务 / 密文仓库

文件服务负责密文生命周期管理：

- 接收客户端上传的密文文件和 `EncryptedFileHeader`。
- 保存文件元数据、接收者列表、密文哈希和审计事件。
- 根据 JWT 限制文件列表、元数据读取和下载。
- 不持有 `MasterSecret`、用户小时私钥或文件明文。

阶段一默认使用本地磁盘模拟密文对象存储，后续可以替换为 NAS 或对象存储。

### 员工客户端 CLI

客户端是唯一接触明文文件的组件，负责：

- 使用模拟 SSO 登录获得 JWT。
- 从 PKG 获取公共参数和当前小时私钥。
- 将文件切分成固定大小 chunk。
- 为每个接收者、每个有效小时、每个 chunk 生成 `RecipientCiphertext`。
- 支持 `BasicIdent` 与 `FullIdent` 两种模式，用于 CPA/CCA 性能对比。
- 上传密文和加密头到文件服务。
- 下载密文后，用当前小时私钥尝试解密。

客户端不持久化过期私钥；当前小时私钥只在会话缓存中保留到小时结束。

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
- PKG 服务端时间是密钥发放的权威来源。
- 客户端可以上传本地时间用于审计，但不能决定私钥小时。
- 所有节点应使用统一 NTP 源同步时间。

## 密钥分发策略

采用客户端 Pull：

1. 客户端携带 JWT 请求 `POST /pkg/private-keys/current`。
2. PKG 校验 JWT、员工状态和授权策略。
3. PKG 使用服务端当前小时构造 `email||YYYY-MM-DD-HH`。
4. PKG 从 `MasterSecret` 派生该小时私钥，返回 `KeyPackage`。
5. 客户端缓存该私钥到当前小时结束。

该策略简化了 PoC 的网络模型，并保持清楚的安全边界：只有认证且活跃的员工能拿到当前小时私钥。

## 加密数据流

1. 客户端获取公共参数。
2. 客户端读取文件明文，并按 `PublicParameters.message_size_bits` 切成定长 chunk。
3. 客户端为每个接收者和有效小时构造 `TimeBoundIdentity`。
4. 在 `BasicIdent` 模式下，每个 chunk 生成论文中的 `C = <U, V>`。
5. 在 `FullIdent` 模式下，每个 chunk 生成论文中的 `C = <U, V, W>`，并在解密时执行 `U = rP` 校验。
6. 客户端将所有 `RecipientCiphertext`、密文块文件和 `EncryptedFileHeader` 上传文件服务。

## 解密数据流

1. 接收者客户端下载密文文件和 `EncryptedFileHeader`。
2. 客户端向 PKG 拉取当前小时私钥。
3. 客户端在 header 中查找自己的 `RecipientCiphertext`。
4. 若 `RecipientCiphertext.time_bound_id` 与当前私钥的 `time_bound_id` 不一致，则拒绝解密。
5. 若一致，客户端按 chunk 顺序运行 BasicIdent 或 FullIdent 解密。
6. FullIdent 对篡改密文执行 `U = rP` 校验，不通过则拒绝；BasicIdent 只作为 IND-ID-CPA 基线，不提供同等级 CCA 篡改检测。

## 严格小时窗口与有效期

阶段一采用严格小时私钥以突出隐式撤销：

- 14:59 加密的文件使用 `YYYY-MM-DD-14` 小时 ID。
- 15:01 客户端只能从 PKG 获取 `YYYY-MM-DD-15` 私钥。
- 若客户端没有保留 14 点私钥，则不能解密 14 点文件。

这使权限撤销能通过“不再发放后续小时私钥”自然生效。课程演示中，这个机制比传统 PKI + CRL 更容易说明频繁权限变化的优势。

为了避免 14:59 发送导致只有 1 分钟可读，文件分发可以设置有效期窗口。客户端加密时按窗口内每个小时为接收者生成一组 `RecipientCiphertext`。例如 14:59 发送、有效期 3 小时，则 header 中包含：

```text
alice@company.com||2026-05-17-14
alice@company.com||2026-05-17-15
alice@company.com||2026-05-17-16
```

接收者在 15 点访问时，只向 PKG 申请当前 15 点私钥，并匹配 15 点密文块；在 17 点之后访问时，PKG 仍只发当前小时私钥，但 header 中没有对应密文块，因此客户端拒绝解密。

本系统不允许历史私钥申请，也不预留历史私钥 API。文件过期后若业务仍需访问，必须由发送者或文件 owner 在当前小时重新分享，生成新的密文头和当前窗口密文块。

## BasicIdent 与 FullIdent 性能实验

阶段二的实验目标是比较“获得 CCA 安全”相对 CPA 基线的开销，而不是证明 CCA 比 CPA 更快。

- BasicIdent 加密密文为 `<U, V>`，解密主要成本是一次 pairing 和一次 `H2` 掩码恢复。
- FullIdent 加密密文为 `<U, V, W>`，增加 `H3`、`H4`、随机 `sigma` 和消息绑定。
- FullIdent 解密除了 pairing，还需要恢复 `sigma`、恢复消息、重新计算 `r = H3(sigma, M)`，并检查 `U = rP`。
- 对大文件直接 IBE 加密时，成本随 `接收者数量 × 有效小时数 × chunk 数量` 线性增长。

建议指标：

- `setup_ms`: 系统参数生成时间。
- `extract_ms`: 每个用户小时私钥派生时间。
- `encrypt_ms`: 单 chunk、单接收者、单小时加密时间。
- `decrypt_ms`: 单 chunk 解密时间。
- `ciphertext_expansion`: BasicIdent `<U,V>` 与 FullIdent `<U,V,W>` 的密文膨胀。
- `tamper_reject_ms`: FullIdent 篡改密文拒绝耗时。

## 威胁边界

本阶段明确以下边界：

- 文件服务泄露：攻击者只能获得密文、加密头和元数据，不能直接解密文件。
- 员工离职或禁用：PKG 不再为该员工 JWT 发放当前小时私钥。
- 密文篡改：阶段二通过 FullIdent 的 Fujisaki-Okamoto 校验拦截；BasicIdent 仅作为 CPA 基线用于对比。
- 时钟漂移：PKG 时间为准，客户端时间只用于审计和偏差提示。

本阶段暂不覆盖生产级 HSM、密钥分片、灾备、多 PKG 高可用、真实 SSO 对接和零信任网络策略。
