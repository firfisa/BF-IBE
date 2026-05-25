# 阶段一 API 文档

API 使用 FastAPI 风格建模。阶段一只定义接口契约和 payload，不要求服务端真实运行。

## 通用约定

- 所有受保护接口使用 `Authorization: Bearer <jwt>`。
- JWT 来自模拟 SSO，包含 `sub`、`email`、`roles`、`active`。
- 时间字段使用 ISO 8601 UTC 字符串。
- 小时字段使用 `YYYY-MM-DD-HH`。
- IBE 时间绑定身份使用 `email||YYYY-MM-DD-HH`。

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
  "scheme": "BF-IBE-FULL",
  "curve": "BN254",
  "pairing": "type-3",
  "generator_g1_b64": "base64...",
  "public_point_b64": "base64...",
  "hash_to_point": "RFC9380-SHA256",
  "kem_kdf": "HKDF-SHA256",
  "version": "pp-2026-05"
}
```

## POST /pkg/private-keys/current

客户端 Pull 当前小时私钥。PKG 使用服务端当前小时，客户端不能指定目标小时。

### Request

```json
{
  "client_time": "2026-05-17T14:30:00Z"
}
```

### Response 200

```json
{
  "subject_email": "alice@company.com",
  "server_hour": "2026-05-17-14",
  "private_key": {
    "time_bound_id": "alice@company.com||2026-05-17-14",
    "recipient_email": "alice@company.com",
    "valid_hour": "2026-05-17-14",
    "private_key_b64": "base64...",
    "issued_at": "2026-05-17T14:30:02Z",
    "expires_at": "2026-05-17T15:00:00Z",
    "public_parameters_version": "pp-2026-05"
  },
  "public_parameters": {
    "scheme": "BF-IBE-FULL",
    "curve": "BN254",
    "pairing": "type-3",
    "generator_g1_b64": "base64...",
    "public_point_b64": "base64...",
    "hash_to_point": "RFC9380-SHA256",
    "kem_kdf": "HKDF-SHA256",
    "version": "pp-2026-05"
  },
  "ntp_policy": "PKG server time is authoritative; clients should sync to corp.ntp.local"
}
```

### Errors

- `401 Unauthorized`: JWT 缺失或无效。
- `403 Forbidden`: 用户未激活、无权限或被撤销。

## POST /files

上传密文文件和加密头。文件服务不接触明文。

### Request

使用 multipart/form-data：

- `ciphertext`: 密文文件。
- `header`: JSON 格式 `EncryptedFileHeader`。

### header 示例

```json
{
  "file_id": "file-001",
  "schema_version": "phase1.v1",
  "algorithm": "BF-IBE-FULL-KEM+A256GCM",
  "encryption_hour": "2026-05-17-14",
  "nonce_b64": "base64...",
  "aad_b64": "base64...",
  "ciphertext_sha256": "abc123",
  "recipients": [
    {
      "recipient_email": "alice@company.com",
      "time_bound_id": "alice@company.com||2026-05-17-14",
      "ibe_capsule_b64": "base64...",
      "encrypted_file_key_b64": "base64..."
    },
    {
      "recipient_email": "bob@company.com",
      "time_bound_id": "bob@company.com||2026-05-17-14",
      "ibe_capsule_b64": "base64...",
      "encrypted_file_key_b64": "base64..."
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

返回当前用户可见的密文文件列表。

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

返回一个密文文件的元数据，不返回密文内容。

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

下载密文文件和加密头。

### Response 200

阶段二实现时建议返回 multipart response 或先返回下载 URL，再由客户端获取密文对象。阶段一约定响应包含：

- `ciphertext`: 密文文件流。
- `header`: JSON 格式 `EncryptedFileHeader`。

### Errors

- `401 Unauthorized`: JWT 缺失或无效。
- `403 Forbidden`: 当前用户既不是 owner，也不在接收者列表中。
- `404 Not Found`: 文件不存在。
