# 数据字典

## UserPrincipal

模拟 SSO JWT 解析后的员工身份。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `subject` | string | 企业身份系统中的稳定用户 ID |
| `email` | string | 员工邮箱，作为 IBE 身份前缀 |
| `roles` | string[] | 员工角色，如 `employee`、`admin` |
| `active` | boolean | 是否允许文件服务提供访问，以及是否允许 PKG 发放任意请求小时的私钥 |

## TimeBoundIdentity

IBE 公钥身份字符串。阶段一固定使用 `email||YYYY-MM-DD-HH`，合法在职用户可向 PKG 申请任意小时对应的私钥。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `email` | string | 小写邮箱 |
| `hour` | string | UTC 小时，格式 `YYYY-MM-DD-HH` |
| `identity` | string | 拼接结果，格式 `email||YYYY-MM-DD-HH` |

示例：

```text
alice@company.com||2026-05-17-14
```

文件 header 会记录加密时使用的小时。接收者访问旧文件时，文件服务先检查接收者当前是否仍是合法员工，再返回密文；随后客户端按 header 中的小时向 PKG 申请对应私钥。

## PublicParameters

所有客户端可见的 BF-IBE 公共参数。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scheme` | string | `BF-IBE-BLS12-381` |
| `curve` | string | `BLS12-381` |
| `pairing` | string | `optimal Ate pairing on BLS12-381, e: G2 x G1 -> GT` |
| `generator_g1_b64` | string | G1 生成元 `P` 序列化值 |
| `public_point_b64` | string | 主公钥点 `Ppub=sP` 的 G1 序列化值 |
| `hash_to_point` | string | Hash-to-Point 方案；当前为 hash_to_G2/SHA-256 |
| `hash_h2` | string | 从 `GT` 配对结果派生种子掩码的哈希 |
| `hash_h3` | string/null | KEM 中从 `sigma` 派生 `r`；FullIdent 对比实验中从 `sigma, M` 派生 `r` |
| `hash_h4` | string/null | KEM 中从 `sigma` 派生 DEM 会话密钥 |
| `message_size_bits` | integer | 论文算法单次加密的定长消息位数 |
| `version` | string | 公共参数版本 |

## MasterSecret

仅 PKG 内部持有的主密钥引用。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `secret_scalar_ref` | string | 主密钥材料引用，阶段一不直接暴露密钥值 |
| `storage_backend` | string | 存储位置，如 `local-dev-vault` |
| `created_at` | datetime | 创建时间 |
| `version` | string | 主密钥版本 |

## PrivateKey

PKG 为合法员工、请求小时派生的 IBE 私钥。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `time_bound_id` | string | 对应 `email||YYYY-MM-DD-HH` |
| `recipient_email` | string | 私钥所属员工邮箱 |
| `valid_hour` | string | 私钥对应的请求小时 |
| `private_key_b64` | string | 序列化私钥；BLS12-381 后端中是 G2 点 `d_ID=sQ_ID` |
| `issued_at` | datetime | PKG 发放时间 |
| `expires_at` | datetime | 客户端缓存过期时间；不改变 `valid_hour` 的密码学含义 |
| `public_parameters_version` | string | 对应公共参数版本 |

## KeyPackage

客户端从 PKG Pull 私钥时拿到的响应包。单小时申请返回一个 `KeyPackage`；时间段申请返回 `KeyPackage` 列表。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `subject_email` | string | 请求者邮箱 |
| `server_hour` | string | PKG 发放时的服务端小时，用于审计 |
| `private_key` | PrivateKey | 请求小时对应的私钥 |
| `public_parameters` | PublicParameters | 当前公共参数 |
| `ntp_policy` | string | 时钟同步策略说明 |

## KemCiphertext

Dent/FO KEM 密文，结构为 `C_KEM=(U,V)`，不包含 FullIdent 的 `W`。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `u_b64` | string | 96 字节 BLS12-381 G1 点 `U=rP` 的序列化值 |
| `v_b64` | string | `sigma xor H2(e(Q_ID,Ppub)^r)` |
| `kem_algorithm` | string | `BF-IBE-DENT-FO-KEM-BLS12-381` |
| `seed_length_bytes` | integer | `sigma` 长度，当前为 32 |
| `key_length_bytes` | integer | KEM 输出 key 长度，当前为 32 |

## RecipientKeyEnvelope

一份文件面向某个接收者的 file key 封装。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `recipient_email` | string | 接收者邮箱 |
| `time_bound_id` | string | 接收者小时 ID |
| `kem_ciphertext` | KemCiphertext | 接收者自己的 BF-IBE KEM 密文 |
| `wrap_iv_b64` | string | 封装 file key 使用的 AES-GCM IV |
| `wrapped_file_key_b64` | string | AES-GCM 输出的 file key 密文和 tag |

## RecipientCiphertext

一份文件面向一个接收者、一个小时、一个 chunk 的直接 IBE 密文条目。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `recipient_email` | string | 接收者邮箱 |
| `time_bound_id` | string | 接收者小时 ID |
| `scheme_mode` | string | `BasicIdent` 或 `FullIdent` |
| `chunk_index` | integer | 文件 chunk 序号 |
| `u_b64` | string | 论文密文分量 `U = rP`；BLS12-381 后端中是 96 字节 G1 点序列化，不保存裸 `r` |
| `v_b64` | string | BasicIdent/FullIdent 的 `V` 分量 |
| `w_b64` | string/null | FullIdent 的 `W` 分量；BasicIdent 为 null |

## EncryptedFileHeader

密文文件头。客户端解密前必须读取。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `file_id` | string | 文件唯一 ID |
| `schema_version` | string | header schema 版本，默认 `phase1.v1` |
| `algorithm` | string | 加密套件，如 `BF-IBE-BASICIDENT-DIRECT-BLS12-381` 或 `BF-IBE-FULLIDENT-DIRECT-BLS12-381` |
| `encryption_hour` | string | 文件加密小时 |
| `ciphertext_sha256` | string | 密文 SHA-256 |
| `recipients` | RecipientCiphertext[] | 多接收者、多小时、多 chunk 密文列表 |
| `chunk_size_bytes` | integer | 每个 IBE 消息 chunk 的字节数 |
| `metadata` | object | 原始文件名等非敏感业务元数据 |

派生属性：

- `recipient_count`: 接收者数量。
- `recipient_ids`: 所有 `time_bound_id` 列表。

该结构保留给 direct BasicIdent/FullIdent 论文对比实验；业务主路径使用 `HybridEncryptedFileHeader`。

## HybridEncryptedFileHeader

KEM/DEM 混合加密文件头。文件正文只保存一份 AES-GCM 密文；接收者差异体现在 `recipient_envelopes`。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `file_id` | string | 文件唯一 ID |
| `schema_version` | string | header schema 版本，默认 `phase2.hybrid.v1` |
| `algorithm` | string | `BF-IBE-DENT-FO-KEMDEM-BLS12-381-AES-256-GCM` |
| `encryption_hour` | string | 文件加密小时 |
| `dem_algorithm` | string | `AES-256-GCM` |
| `dem_iv_b64` | string | 文件正文 AES-GCM IV |
| `dem_tag_b64` | string | 文件正文 AES-GCM tag |
| `recipient_envelopes` | RecipientKeyEnvelope[] | 每个接收者的 KEM/DEM key envelope |
| `ciphertext_sha256` | string | 文件正文密文 SHA-256 |
| `metadata` | object | 原始文件名等非敏感业务元数据 |

## FileMetadata

文件服务保存的密文对象元数据。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `file_id` | string | 文件唯一 ID |
| `owner_email` | string | 上传者邮箱 |
| `original_filename` | string | 原始文件名 |
| `size_bytes` | integer | 密文大小 |
| `encryption_hour` | string | 加密小时 |
| `recipients` | string[] | 接收者邮箱列表 |
| `ciphertext_sha256` | string | 密文 SHA-256 |
| `created_at` | datetime | 上传时间 |

## AuditEvent

PKG 和文件服务的审计事件。文件服务应记录 active 校验失败、非 owner/recipient 访问、下载成功等事件；PKG 应记录私钥发放和拒绝事件。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | string | 事件 ID |
| `actor_email` | string | 操作人邮箱 |
| `action` | string | 操作类型，如 `ISSUE_PRIVATE_KEY`、`UPLOAD_FILE` |
| `target` | string | 目标对象，如文件 ID 或 time-bound ID |
| `occurred_at` | datetime | 服务端事件时间 |
| `client_time` | datetime/null | 客户端上报时间，可用于时钟偏差审计 |
| `metadata` | object | 附加字段 |
