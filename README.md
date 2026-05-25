# BF-IBE Enterprise File Distribution PoC

这是一个基于 Boneh-Franklin IBE 思路的企业内部加密文件分发系统课程 PoC。当前仓库完成的是阶段一：总体架构、系统设计与接口建模。

## Current Scope

- 明确三类核心实体：PKG 企业密钥中心、文件服务/密文仓库、员工客户端 CLI。
- 默认时间绑定身份格式：`email||YYYY-MM-DD-HH`；PKG 不提供历史私钥申请接口。
- 采用客户端 Pull 的小时私钥分发策略。
- 文件服务只保存密文、加密头和审计元数据，不接触明文。
- 提供 Python 空接口代码和数据模型，阶段二直接实现论文中的 BasicIdent 与 FullIdent，并比较 IND-ID-CPA 与 IND-ID-CCA 模式的运行开销。

## Repository Map

- [docs/architecture.md](docs/architecture.md): 系统架构、组件职责、数据流、时钟策略、威胁边界。
- [docs/diagrams.md](docs/diagrams.md): Mermaid 架构图、部署图和关键流程图。
- [docs/api.md](docs/api.md): FastAPI 风格 REST API 契约。
- [docs/data-dictionary.md](docs/data-dictionary.md): 核心数据字典。
- [bf_ibe_phase1/models.py](bf_ibe_phase1/models.py): 阶段一数据模型。
- [bf_ibe_phase1/crypto_interfaces.py](bf_ibe_phase1/crypto_interfaces.py): 业务加解密接口。
- [bf_ibe_phase1/service_interfaces.py](bf_ibe_phase1/service_interfaces.py): PKG 与文件服务客户端接口。

## Verify

```bash
python3 -m unittest discover -s tests -v
```
