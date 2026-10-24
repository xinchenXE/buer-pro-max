---
name: buer-pro-max
description: Bootstrap a cross-session governance framework into any repository — plan containers, numbered ID sequences, a register/dispatch/execute authorization state machine, deviation and issue ledgers, evidence discipline, and a project constitution written into AGENTS.md. Use when the user asks to set up project governance, a plan/decision tracking system, a working-paradigm or development-paradigm document, a queue register, round-based work records, or says "治理框架", "建立治理", "开发范式", "登记队列", "建立计划体系", "给这个项目建一套规矩", "bootstrap governance", "set up a dev paradigm", "add a governance scaffold". Also triggers when a repo already has such a framework and the user wants it audited, extended, or has a project where sessions keep losing context between rounds.
license: MIT
compatibility: Requires a POSIX shell (bash / zsh / git-bash) for the due-diligence probe commands in references/due-diligence.md; on Windows run them under git-bash, or substitute the equivalent PowerShell commands. Reading this skill requires no runtime; maintaining it (scripts/selfcheck.py) needs Python 3.
metadata:
  author: xinchenXE(布耶尔)
  version: "1.3.1"
---

# buer-pro-max · 治理框架初始化（Governance Framework Bootstrap）

把一个**跨会话的项目治理体系**装进任意仓库。

> **目的：尽最大可能降低返工概率，一次性做对。**
> 下面每一条规则存在的理由都是「不写它就会返工」，不是「写了更好看」。
> **判定一条规则要不要写，只问：「不写会不会返工？」** ——
> 会 → 必选；只在某个主题物存在时才可能 → 可选（写明触发）；
> 什么都不会发生 → 参考。详见 `references/mandatory-vs-optional.md`。

它的核心不是文档模板，而是四条约束：

1. **没有派发就没有执行权** —— 「登记」「派发」「执行」是三段互不推定的授权。
2. **先计划后实施** —— 未落计划文档的改动不进代码。
3. **门禁全绿才算完成** —— 且完成宣告是一套固定仪式，不是一句「做完了」。
4. **证据不自证** —— 走查/验证结论不得由执行者自己打勾。

这套体系原本在一个 6 万行、单人、跨会话、有外部上游的桌面产品上跑了 70+ 轮。
本 skill 把它抽成骨架，**先尽调目标项目再裁剪生成**——不是每次都吐同一套。

---

## 什么时候用

- 用户要在**新项目**里建一套计划/队列/偏差/问题的追踪体系。
- 用户抱怨「每次新会话都丢掉上文」「上一轮改了什么没人知道」「计划写了没人按计划走」。
- 用户已有零散文档，想要一个统一的信息架构。
- 用户已有治理体系，要**审计**它缺什么 / 哪里违反了自己的规则（→ 走 §四）。

**不适用**：一次性的小脚本、单人单次的实验、已经用 issue tracker + CI 覆盖得很好的团队项目。
装一套治理体系的成本是真实的；用错地方比没有更糟。先看 §一 的尽调结论。

---

## 一、尽调（必做，不许跳）

生成任何东西之前，先跑一遍探测。**探不到的就问用户，不要猜，也不要留空转的占位文件。**

### 1.1 必探项

| 探什么 | 怎么探 | 用途 |
|---|---|---|
| 有没有 VCS | `.git` / `.hg` 存在性 | 决定「快照」是必需还是可选（§二 档位表） |
| 有没有外部上游 | git submodule、vendored 目录、`upstream.json` 之类、monorepo 外依赖、fork 标记 | 决定铁律 1/2 是否启用（§二） |
| 本体的边界在哪 | 哪些目录是「自己的」，哪些是「继承来的」 | 决定可写范围（几处由本项目定；§二） |
| 真实门禁命令 | `package.json` scripts / `Makefile` / `pyproject.toml` / `Cargo.toml` / CI 配置 | 填充门禁表；探不到的写「不适用 + 原因」 |
| 已有文档体系 | 现有 `AGENTS.md` / `CLAUDE.md` / `docs/` / `README` | 决定是**并入**还是**新建**，绝不覆盖 |
| 规模 | 源文件数、代码行数、目录深度 | 决定轻量/标准/完整档 |
| 是否多人协作 | `CODEOWNERS`、`CONTRIBUTING.md`、CI 上的 PR 检查 | 决定授权口径是否要引入第二人 |

**先确认 shell**：本节命令是 POSIX 的；Windows 上先看
`references/due-diligence.md` §一.0 的预检与替换表（**不要照抄 `2>/dev/null`**）。

用 `references/due-diligence.md` 里的清单逐条过，结果写进交付的 `docs/governance/项目清单/尽调结论.md`
（**微型档例外** —— 那个档不生成 `docs/governance/`，尽调结论写进 `NEXT.md` 的「已决定」节）。

### 1.2 必问用户的问题（**五条提问** + 推荐项说明）

尽调能探到的不要问。探不到、且答案会改变生成结果的，**必须问**：

1. **「这个项目里，哪些目录是绝对不许改的？」** —— 上游、生成物、第三方、配置。答案直接决定可写范围表和宪法里的硬停清单。**如果用户说「都能改」，把这条记下来**：那意味着这套体系里最独特的铁律（零上游改动 / 只经公开面集成）不启用，别硬塞。
2. **「改动造成损失时，你能接受的回滚手段是什么？」** —— 有 git → 快照可选；无 git → 快照是**唯一退路**，必须进宪法的硬停清单。
3. **「谁有最终拍板权，什么情况下你会亲自发话？」** —— 决定「特别授权」的口径。单人项目答案通常是「只有我」，那就把「泛泛的继续/go ahead 不构成授权」写死。
4. **「这套体系里，你最怕发生什么？」** —— **开放题**，答案决定生成件的侧重（完整选项见 `references/due-diligence.md` §二）：
   - 「怕新会话不知道我在干什么」→ 交接机制、默认阅读顺序、宪法段
   - 「怕改了不该改的」→ 可写范围、硬停清单、当轮授权
   - 「怕计划写了没人执行」→ 状态机、闭环仪式、完成定义
   - 「怕数字对不上」→ 计数唯一真源、文档同步纪律
5. **「治理文档的目录和文件名，用中文还是英文？」** —— 默认**中文**；目标仓库是英文项目 / 需跨语区分发 / 有 CI 处理路径时建议**英文**。选定后整棵树只用那一套，**不要混用**。对照表见 `references/naming.md`。

**另外还有「推荐项」——它不是提问，不要混进上面四条**（见 `references/mandatory-vs-optional.md` §六）
**在初始化前连同尽调结论一起说明**。**每一项必须讲全三段，缺一不可**：

**① 为什么推荐**（防什么，具体到会怎么返工 / 会花多久）·
**② 成本影响**（一次性多少 + 长期每轮多少 + 有无额外依赖）·
**③ 不做的后果**。

**三段都要落到可比较的量上**；讲不出量，说明还没想清楚这条值不值。
用户点头就做，不点头就跳过。**目前有两项**：

- `工作范式.md` §六「环境事实」一节
- 会话交接件（`登记提示词/`，闭环仪式第 8 件）

---

## 二、裁剪：五档

选档依据是尽调结果，不是用户偏好。**宁可先低一档**——框架是可以长上去的，多余的容器只会变成噪音。

**详细判据、项目画像、升降档信号见 `references/tier-selection.md`。**
**下表是速查；判据权威是 `tier-selection.md` §一，铁律权威是 `iron-rules.md` 顶部的「档位 → 铁律 ID」表。**

| | **微型** | **轻量** | **标准** | **完整** | **重型** |
|---|---|---|---|---|---|
| **适用** | 单文件脚本 / 周末实验 | 单人小工具或库 | 单人/小团队主力项目 | 跨会话长周期产品 | 多仓库 / 多角色 / 有发布与合规 |
| **判据** | 1–2 个源文件，不打算回来维护 | < 5k 行；无外部上游；改动面 1 个目录 | 5k–50k 行；2–3 个目录；跨会话 | > 50k 行，或 > 20 轮历史 | 多个维护者；发布列车；审计要求 |
| **计划容器** | 无 | 活跃 / 归档 | + 休眠 / 归档文档 | 全部五个 | 全部五个 + 按流向分子目录 |
| **ID 序列** | 无 | 队列 + 轮次 | + 问题 | + 偏差（四序列） | 四序列 + 命名空间前缀 |
| **台账** | 无 | 队列总表 | + 问题记录 / 修改记录 | + 偏差总账 / 操作记录 | + 审计台账 / 发布台账 |
| **闭环仪式** | 无（提交即闭环） | 3 步 | 5 步 | 7 步 | 7 步 + 发布门 + 双人签署 |
| **铁律**（按 ID，见 `iron-rules.md` 顶部） | 无 | ③ | ③④⑤⑥ | ③④⑤⑥ + ①②（按触发） | 同完整 + 契约化（角色矩阵） |
| **宪法段长度** | 不写 | ~40 行 | ~100 行 | ~200 行 | ~200 行 + 角色/权限矩阵 |
| **生成动作** | **什么都不生成** | 最小集（树见 `tier-selection.md` §四） | 默认集（树见 §三） | 全部 | 全部 + 角色矩阵 + 发布台账 |
| **可选容器**<br>（用户可推翻，见 §三·补） | — | `缓存/` 视需要 | `证据/` + `缓存/` | `工具/` + 前三者 | 同完整档 |
| **`快照/`** | — | 无 VCS 才要 | 无 VCS 才要 | 无 VCS 才要 | 无 VCS 才要 |

**微型档的正确处置是「不装」** —— 给一份约 15 行的 `NEXT.md` 模板，说明为什么这个规模
装治理只有坏处。**如果尽调判出微型，不要生成 `docs/governance/`。**

**重型档多出来的不是文档，是三个机制**：角色与权限矩阵、不可变台账、发布列车与版本纪律。
单人项目里这套框架解决「跨会话失忆」；重型项目里它解决「多角色之间谁有权做什么」——
把完整档原样放大只会得到一份没人读的宪法。

**升降档是双向的**（见 `tier-selection.md` §六）：连续 10 轮没有新 `ISS`/`DEV`、
某容器长期空转、只有一个人自问自答 → **考虑降档**。
**降档的正确做法是在容器 README 里标注「暂停使用 + 原因」，不是删文件**——
历史记录不可恢复，删掉它等于抹掉「当时到底发生了什么」。

**档位可以混合**：monorepo 里各子项目各自一档是正常且推荐的。

---

## 三、生成（标准档为默认；按 §二 增减）

生成 `docs/governance/` 文档树 + 一段写进 `AGENTS.md` 的**宪法段**。

**完整生成树**（含每个容器的模板对照、重型档的两个机制容器）、
「每个容器都要有 README」、`缓存/` 的两条纪律、两处刻意的合并、
以及**生成时的三条纪律** —— 都在 **`references/gen-tree.md`**。

**最小记忆点**：

- 每个容器都要有 `README.md`（放什么 / 怎么进 / 怎么出 / **不在这里放什么**）。
- **不发明命令**：门禁表只填尽调探到的真命令，探不到的写「不适用 + 原因」。
- **不覆盖既有文件**：`AGENTS.md` 已有内容 → 末尾追加，绝不覆盖。
- **每个占位符都要有主**：填不了就删掉那一节，不留永远填不上的空。
- **微型档只生成一份 `NEXT.md`**，不生成上面的树。

---

## 三·补、可选容器：由用户选，默认值挂档位

`证据/` `缓存/` `工具/` `快照/` 这四个容器**不是每档都生成**，
各自解决一类问题；**问题不存在的项目不该有它们**。

**判定顺序、触发信号表、三条纪律、以及在 `docs/governance/README.md` 里怎么写，
见 `references/optional-containers.md`。**


## 四、审计与演进模式（对已有框架）

对**已有治理体系**的项目：审计它缺什么 / 哪里违反了自己的规则，
以及**演进**它（加容器 / 升档 / 降档）。

**完整清单与操作面在 `references/audit-and-evolve.md`。** 一句话：

- **审计**：提取目标项目**自己声明的**规则，逐条核对实际状态，
  报告三类问题 —— **已违反自己的规则** / **规则有但没人能执行** / **规则缺口**。
  **不按本 skill 的模板去「修正」目标项目** —— 它的规则载体是权威。
- **演进**：三种动作（加容器 / 升档 / 降档），**都不改历史**；
  降档不删文件，升档不跳步，演进本身必须留痕。


## 五、规则正文去哪找

| 想了解 | 读 |
|---|---|
| 尽调清单、探测命令、要问用户的原始问题 | `references/due-diligence.md` |
| **五档判据、项目画像、升降档信号、重型档的三个机制** | `references/tier-selection.md` |
| 六条铁律（含零上游改动 / 只经公开面集成怎么拆两层） | `references/core/iron-rules.md` |
| 可写范围怎么划（A–X 档位的通用形式） | `references/core/writable-scope.md` |
| 四套 ID 序列、永不复用、前缀可配 | `references/core/id-sequences.md` |
| 登记 / 派发 / 执行三段授权，同轮直授旁路 | `references/core/authorization-state-machine.md` |
| 五个计划容器的分类规则与生命周期 | `references/core/plan-containers.md` |
| 完成宣告与闭环仪式（三/五/七步） | `references/core/completion-ritual.md` |
| 门禁表怎么填、硬停清单怎么定 | `references/core/gates-and-holds.md` |
| 文档同步纪律、规则载体多处同步、静默跳过=漏做 | `references/core/doc-sync-discipline.md` |
| **踩过的坑与「为什么需要它」**（这是框架里最难自己长出来的部分） | `references/anti-patterns.md` |
| 会话交接件（跨会话不失忆） | `references/session-handoff.md` |
| **门禁脚本怎么实现**（文档基线同步 / 引用完整性 / 快照 / 走查包装的契约） | `references/tool-contracts.md` |
| **哪些规则必选、哪些可选**（触发条件索引；生成时按它裁剪） | `references/mandatory-vs-optional.md` |
| **产物用中文还是英文命名**（生成前问用户；两套对照表） | `references/naming.md` |
| **维护本 skill 自身**（只改这 39 份 md 时用，**不作用于目标项目**） | `scripts/selfcheck.py` |

模板在 `templates/`，按上面 §三 的树对号入座。每个模板的头部注释说明它**为什么存在**与**什么时候不该用**。

---

## 六、生成后自检

交付前逐条确认的清单在 **`references/self-check.md`**。
**任何一条不过就回去补** —— 全部通过才算闭合。
