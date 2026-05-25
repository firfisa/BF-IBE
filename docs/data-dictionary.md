# 阶段一数据字典

## UserPrincipal

模拟 SSO JWT 解析后的员工身份。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `subject` | string | 企业身份系统中的稳定用户 ID |
| `email` | string | 员工邮箱，作为 IBE 身份前缀 |
| `roles` | string[] | 员工角色，如 `employee`、`admin` |
| `active` | boolean | 是否允许 PKG 发放当前小时私钥 |

## TimeBoundIdentity

IBE 公钥身份字符串。阶段一固定使用 `email||YYYY-MM-DD-HH`，PKG 不发放历史小时私钥。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `email` | string | 小写邮箱 |
| `hour` | string | UTC 小时，格式 `YYYY-MM-DD-HH` |
| `identity` | string | 拼接结果，格式 `email||YYYY-MM-DD-HH` |

示例：

```text
alice@company.com||2026-05-17-14
```

若一个文件需要 3 小时有效期，客户端会在 header 中为同一接收者放入 3 个不同小时的 `RecipientCiphertext`。过期后不申请旧小时私钥，而是由发送者重新分享。

## PublicParameters

所有客户端可见的 BF-IBE 公共参数。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scheme` | string | `BF-IBE-DIRECT` |
| `curve` | string | 椭圆曲线或双线性群参数名称 |
| `pairing` | string | 配对类型描述 |
| `generator_g1_b64` | string | G1 生成元序列化值 |
| `public_point_b64` | string | 主公钥点序列化值 |
| `hash_to_point` | string | Hash-to-Point 方案 |
| `hash_h2` | string | BasicIdent/FullIdent 中从 `G2` 派生掩码的哈希 |
| `hash_h3` | string/null | FullIdent 中从 `sigma, M` 派生 `r` 的哈希 |
| `hash_h4` | string/null | FullIdent 中从 `sigma` 派生消息掩码的哈希 |
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

PKG 为当前员工、当前小时派生的 IBE 私钥。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `time_bound_id` | string | 对应 `email||YYYY-MM-DD-HH` |
| `recipient_email` | string | 私钥所属员工邮箱 |
| `valid_hour` | string | 私钥有效小时 |
| `private_key_b64` | string | 序列化私钥 |
| `issued_at` | datetime | PKG 发放时间 |
| `expires_at` | datetime | 当前小时结束时间 |
| `public_parameters_version` | string | 对应公共参数版本 |

## KeyPackage

客户端从 PKG Pull 私钥时拿到的响应包。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `subject_email` | string | 请求者邮箱 |
| `server_hour` | string | PKG 服务端当前小时 |
| `private_key` | PrivateKey | 当前小时私钥 |
| `public_parameters` | PublicParameters | 当前公共参数 |
| `ntp_policy` | string | 时钟同步策略说明 |

## RecipientCiphertext

一份文件面向一个接收者、一个小时、一个 chunk 的直接 IBE 密文条目。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `recipient_email` | string | 接收者邮箱 |
| `time_bound_id` | string | 接收者小时 ID |
| `scheme_mode` | string | `BasicIdent` 或 `FullIdent` |
| `chunk_index` | integer | 文件 chunk 序号 |
| `u_b64` | string | 论文密文分量 `U = rP` |
| `v_b64` | string | BasicIdent/FullIdent 的 `V` 分量 |
| `w_b64` | string/null | FullIdent 的 `W` 分量；BasicIdent 为 null |

## EncryptedFileHeader

密文文件头。客户端解密前必须读取。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `file_id` | string | 文件唯一 ID |
| `schema_version` | string | header schema 版本，默认 `phase1.v1` |
| `algorithm` | string | 加密套件，如 `BF-IBE-BASICIDENT-DIRECT` 或 `BF-IBE-FULLIDENT-DIRECT` |
| `encryption_hour` | string | 文件加密小时 |
| `ciphertext_sha256` | string | 密文 SHA-256 |
| `recipients` | RecipientCiphertext[] | 多接收者、多小时、多 chunk 密文列表 |
| `chunk_size_bytes` | integer | 每个 IBE 消息 chunk 的字节数 |
| `metadata` | object | 原始文件名等非敏感业务元数据 |

派生属性：

- `recipient_count`: 接收者数量。
- `recipient_ids`: 所有 `time_bound_id` 列表。

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

PKG 和文件服务的审计事件。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | string | 事件 ID |
| `actor_email` | string | 操作人邮箱 |
| `action` | string | 操作类型，如 `ISSUE_PRIVATE_KEY`、`UPLOAD_FILE` |
| `target` | string | 目标对象，如文件 ID 或 time-bound ID |
| `occurred_at` | datetime | 服务端事件时间 |
| `client_time` | datetime/null | 客户端上报时间，可用于时钟偏差审计 |
| `metadata` | object | 附加字段 |
