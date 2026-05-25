# 阶段一 API 文档

API 使用 FastAPI 风格建模。阶段一只定义接口契约和 payload，不要求服务端真实运行。

## 通用约定

- 所有受保护接口使用 `Authorization: Bearer <jwt>`。
- JWT 来自模拟 SSO，包含 `sub`、`email`、`roles`、`active`。
- 时间字段使用 ISO 8601 UTC 字符串。
- 小时字段使用 `YYYY-MM-DD-HH`。
- IBE 时间绑定身份使用 `email||YYYY-MM-DD-HH`。
- 合法在职用户可以向 PKG 申请任意小时或时间段的私钥。
- PKG 发放私钥时只信任服务端员工状态；离职、禁用或 JWT 无效时拒绝所有小时申请。
- 文件服务在列表、元数据读取、下载前也必须校验员工 active 状态。

## POST /auth/mock-login

模拟企业 SSO 登录，供课程 PoC 使用。

### Request

```json
{
  "email": "alice@company.com",
  "password": "demo-password"
}
```

### Response 200

```json
{
  "access_token": "mock.jwt.token",
  "token_type": "bearer",
  "expires_in": 3600,
  "principal": {
    "subject": "user-alice",
    "email": "alice@company.com",
    "roles": ["employee"],
    "active": true
  }
}
```

## GET /pkg/public-parameters

返回当前 BF-IBE 公共参数。客户端加密前必须获取。

### Response 200

```json
{
  "scheme": "BF-IBE-DIRECT",
  "curve": "BN254",
  "pairing": "type-3",
  "generator_g1_b64": "base64...",
  "public_point_b64": "base64...",
  "hash_to_point": "RFC9380-SHA256",
  "hash_h2": "SHA256-to-mask",
  "hash_h3": "SHA256-to-Zq",
  "hash_h4": "SHA256-to-mask",
  "message_size_bits": 256,
  "version": "pp-2026-05"
}
```

## POST /pkg/private-keys/request

客户端 Pull 指定小时或时间段的私钥。PKG 不限制请求小时是否在过去，只校验用户当前是否仍为合法员工。

### Request

```json
{
  "requested_hours": [
    "2026-05-17-02",
    "2026-05-17-03",
    "2026-05-17-04"
  ],
  "client_time": "2026-05-17T08:30:00Z",
  "reason": "decrypt files received earlier today"
}
```

### Response 200

```json
{
  "subject_email": "alice@company.com",
  "server_time": "2026-05-17T08:30:02Z",
  "keys": [
    {
      "time_bound_id": "alice@company.com||2026-05-17-02",
      "recipient_email": "alice@company.com",
      "valid_hour": "2026-05-17-02",
      "private_key_b64": "base64...",
      "issued_at": "2026-05-17T08:30:02Z",
      "expires_at": "2026-05-17T09:00:00Z",
      "public_parameters_version": "pp-2026-05"
    },
    {
      "time_bound_id": "alice@company.com||2026-05-17-03",
      "recipient_email": "alice@company.com",
      "valid_hour": "2026-05-17-03",
      "private_key_b64": "base64...",
      "issued_at": "2026-05-17T08:30:02Z",
      "expires_at": "2026-05-17T09:00:00Z",
      "public_parameters_version": "pp-2026-05"
    }
  ],
  "public_parameters": {
    "scheme": "BF-IBE-DIRECT",
    "curve": "BN254",
    "pairing": "type-3",
    "generator_g1_b64": "base64...",
    "public_point_b64": "base64...",
    "hash_to_point": "RFC9380-SHA256",
    "hash_h2": "SHA256-to-mask",
    "hash_h3": "SHA256-to-Zq",
    "hash_h4": "SHA256-to-mask",
    "message_size_bits": 256,
    "version": "pp-2026-05"
  },
  "authorization_policy": "keys are issued only while the employee is active",
  "ntp_policy": "PKG server time is authoritative for audit and employee-state checks"
}
```

### Errors

- `401 Unauthorized`: JWT 缺失或无效。
- `403 Forbidden`: 用户离职、被禁用或不再是合法员工。

## POST /files

上传密文文件和加密头。文件服务不接触明文，但会校验上传者 JWT 和员工 active 状态。

### Request

使用 multipart/form-data：

- `ciphertext`: 密文文件。
- `header`: JSON 格式 `EncryptedFileHeader`。

### header 示例

```json
{
  "file_id": "file-001",
  "schema_version": "phase1.v1",
  "algorithm": "BF-IBE-FULLIDENT-DIRECT",
  "encryption_hour": "2026-05-17-14",
  "chunk_size_bytes": 32,
  "ciphertext_sha256": "abc123",
  "recipients": [
    {
      "recipient_email": "alice@company.com",
      "time_bound_id": "alice@company.com||2026-05-17-14",
      "scheme_mode": "FullIdent",
      "chunk_index": 0,
      "u_b64": "base64...",
      "v_b64": "base64...",
      "w_b64": "base64..."
    },
    {
      "recipient_email": "bob@company.com",
      "time_bound_id": "bob@company.com||2026-05-17-14",
      "scheme_mode": "BasicIdent",
      "chunk_index": 0,
      "u_b64": "base64...",
      "v_b64": "base64...",
      "w_b64": null
    }
  ],
  "metadata": {
    "original_filename": "finance-report.pdf"
  }
}
```

### Response 201

```json
{
  "file_id": "file-001",
  "owner_email": "alice@company.com",
  "original_filename": "finance-report.pdf",
  "size_bytes": 1048576,
  "encryption_hour": "2026-05-17-14",
  "recipients": [
    "alice@company.com",
    "bob@company.com"
  ],
  "ciphertext_sha256": "abc123",
  "created_at": "2026-05-17T14:31:00Z"
}
```

## GET /files

返回当前 active 用户可见的密文文件列表。离职或禁用用户返回 `403 Forbidden`。

### Response 200

```json
[
  {
    "file_id": "file-001",
    "owner_email": "alice@company.com",
    "original_filename": "finance-report.pdf",
    "size_bytes": 1048576,
    "encryption_hour": "2026-05-17-14",
    "recipients": ["alice@company.com", "bob@company.com"],
    "ciphertext_sha256": "abc123",
    "created_at": "2026-05-17T14:31:00Z"
  }
]
```

## GET /files/{file_id}

返回一个密文文件的元数据，不返回密文内容。文件服务必须确认用户仍 active，且用户是 owner 或 recipient。

### Response 200

```json
{
  "file_id": "file-001",
  "owner_email": "alice@company.com",
  "original_filename": "finance-report.pdf",
  "size_bytes": 1048576,
  "encryption_hour": "2026-05-17-14",
  "recipients": ["alice@company.com", "bob@company.com"],
  "ciphertext_sha256": "abc123",
  "created_at": "2026-05-17T14:31:00Z"
}
```

## GET /files/{file_id}/download

下载密文文件和加密头。文件服务必须确认用户仍 active，且用户是 owner 或 recipient。

### Response 200

阶段二实现时建议返回 multipart response 或先返回下载 URL，再由客户端获取密文对象。阶段一约定响应包含：

- `ciphertext`: 密文文件流。
- `header`: JSON 格式 `EncryptedFileHeader`。

### Errors

- `401 Unauthorized`: JWT 缺失或无效。
- `403 Forbidden`: 当前用户已离职、被禁用，或既不是 owner 也不在接收者列表中。
- `404 Not Found`: 文件不存在。

## POST /benchmarks/ibe

阶段二实验接口，用于比较论文 BasicIdent 与 FullIdent 的运行时间和密文膨胀。该接口不参与文件分发主流程，可由 CLI 或测试脚本调用。

### Request

```json
{
  "modes": ["BasicIdent", "FullIdent"],
  "message_size_bits": 256,
  "chunk_count": 100,
  "recipient_count": 1,
  "valid_hours": 3,
  "repeat": 30,
  "tamper_test": true
}
```

### Response 200

```json
{
  "results": [
    {
      "mode": "BasicIdent",
      "security_target": "IND-ID-CPA",
      "encrypt_ms_avg": 1.2,
      "decrypt_ms_avg": 1.5,
      "ciphertext_components": ["U", "V"],
      "ciphertext_expansion_bytes_avg": 96,
      "tamper_rejection": "not provided by BasicIdent"
    },
    {
      "mode": "FullIdent",
      "security_target": "IND-ID-CCA",
      "encrypt_ms_avg": 1.4,
      "decrypt_ms_avg": 2.0,
      "ciphertext_components": ["U", "V", "W"],
      "ciphertext_expansion_bytes_avg": 128,
      "tamper_reject_ms_avg": 2.1
    }
  ]
}
```
