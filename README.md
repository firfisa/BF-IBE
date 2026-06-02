# BF-IBE Enterprise File Distribution PoC

这是一个基于 Boneh-Franklin IBE 思路的企业内部加密文件分发系统课程 PoC。当前仓库已完成阶段一设计，并开始阶段二密码学内核接入。

## Current Scope

- 明确三类核心实体：PKG 企业密钥中心、文件服务/密文仓库、员工客户端 CLI。
- 默认时间绑定身份格式：`email||YYYY-MM-DD-HH`；合法在职用户可向 PKG 申请任意小时或时间段的私钥。
- 采用客户端 Pull 的私钥分发策略，PKG 在发放时校验员工是否仍在职。
- 文件服务只保存密文、加密头和审计元数据，不接触明文；下载前会校验用户是否仍是合法员工。
- 默认业务加密路径使用 BF-IBE Dent/FO KEM + AES-256-GCM DEM；BasicIdent/FullIdent direct IBE 保留为论文对比实验。

## Repository Map

- [docs/architecture.md](docs/architecture.md): 系统架构、组件职责、数据流、时钟策略、威胁边界。
- [docs/diagrams.md](docs/diagrams.md): Mermaid 架构图、部署图和关键流程图。
- [docs/api.md](docs/api.md): FastAPI 风格 REST API 契约。
- [docs/data-dictionary.md](docs/data-dictionary.md): 核心数据字典。
- [bf_ibe_phase1/models.py](bf_ibe_phase1/models.py): 阶段一数据模型。
- [bf_ibe_phase1/crypto_core.py](bf_ibe_phase1/crypto_core.py): BLS12-381 pairing 版 BasicIdent/FullIdent 与 Dent/FO KEM。
- [bf_ibe_phase1/auth.py](bf_ibe_phase1/auth.py): 模拟 SSO/JWT 与员工 active 状态管理。
- [bf_ibe_phase1/demo_services.py](bf_ibe_phase1/demo_services.py): 可运行的 PKG 服务和文件服务实现。
- [bf_ibe_phase1/direct_file_crypto.py](bf_ibe_phase1/direct_file_crypto.py): 直接 IBE 文件 chunk 加解密器。
- [bf_ibe_phase1/hybrid_file_crypto.py](bf_ibe_phase1/hybrid_file_crypto.py): KEM/DEM 混合文件加解密器。
- [bf_ibe_phase1/crypto_interfaces.py](bf_ibe_phase1/crypto_interfaces.py): 业务加解密接口。
- [bf_ibe_phase1/service_interfaces.py](bf_ibe_phase1/service_interfaces.py): PKG 与文件服务客户端接口。
- [bf_ibe_phase1/demo.py](bf_ibe_phase1/demo.py): 一键演示入口。

## Verify

```bash
conda activate bf-ibe
python -m unittest discover -s tests -v
```

## Demo

```bash
conda activate bf-ibe
python -m bf_ibe_phase1.demo
```

演示内容：

- Alice 使用 Dent/FO KEM + AES-256-GCM 加密文件并上传到文件服务。
- Bob 在之后的时间访问旧文件，文件服务校验 Bob 仍是 active 员工，PKG 发放文件 header 中对应小时的私钥。
- Bob 离职后，文件服务拒绝下载，PKG 也拒绝发放任意小时私钥。
- 输出业务 KEM/DEM 流程结果，以及 BasicIdent 和 FullIdent 的简单运行时间对比。

当前默认密码学核心使用 BLS12-381 非对称 Type-3 pairing：身份点和私钥在 G2，`Ppub` 与 `U=rP` 在 G1，配对函数为 `py_ecc.optimized_bls12_381.pairing(Q_G2, P_G1)`。`ToyBFIBE` 仍保留为课程讲解时的轻量对照。
