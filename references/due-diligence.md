# 尽调清单（初始化第一步）

> **目的**：让生成的框架落在目标项目的**真实状态**上，而不是一套通用口号。
> 本清单的每一条都要产出**可核对的结果**（命令 + 输出，或文件路径），不写推测。
> 结果汇总写进交付的 `<GOV_ROOT>/项目清单/尽调结论.md`。

---

## 一、必探项

### 0. 先确认你在哪个 shell（10 秒，**别跳**）

本节所有命令都是 **POSIX shell**（bash / zsh / git-bash）。在 Windows 的
PowerShell / cmd 里直接照抄会**静默出错**：

- `find` 会解析到 `C:\Windows\System32\find.exe` —— **那是另一个程序**（文本搜索）；
- `grep` / `head` / `wc` **不存在**；
- **`2>/dev/null` 在 PowerShell 里会造出一个名叫 `/dev/null` 的怪文件**（不是丢弃输出）。

**探测是第一步且必做** —— 探错了，后面的档位判定与门禁表全错。所以先确认环境：

```sh
uname -s 2>/dev/null || echo "not POSIX"
```

| 输出 | 你在哪 | 怎么办 |
|---|---|---|
| 含 `Linux` / `Darwin` / `MINGW` / `MSYS` | POSIX（含 git-bash） | ✅ 下面的命令**逐字可用** |
| `not POSIX` 或报错 | PowerShell / cmd | ⚠️ **先看替换表**，或**换 git-bash 重跑** |

> **推荐：Windows 上优先用 git-bash。** 它是唯一能保证与本节命令**逐字一致**的环境。
> 替换表是**兜底**，不是首选 —— 每次手写等价命令，就多一次「写出来的探测和原文不一样」的机会，
> 而探测不一致正是**判错档位的根因**。

#### POSIX → PowerShell 替换表（兜底用）

| POSIX | PowerShell 等价 | 陷阱 |
|---|---|---|
| `find . -name "*.ts"` | `Get-ChildItem -Recurse -Filter *.ts` | **不是同一个 `find`** |
| `find . \( -name a -o -name b \)` | `Get-ChildItem -Recurse -Include a,b` | 注意 `-Include` 需配合 `-Recurse` |
| `find . -not -path "*/node_modules/*"` | `... \| Where-Object FullName -NotMatch 'node_modules'` | |
| `grep -rl "x" .` | `Select-String -Path .\* -Pattern "x" -List` | `-List` ≈ `-l` |
| `grep -A30 '"scripts"' package.json` | `Get-Content package.json \| Select-String '"scripts"' -Context 0,30` | |
| `head -20` | `Select-Object -First 20` | |
| `wc -l` | `Measure-Object -Line` | 对**行**统计，不是文件数 |
| `2>/dev/null` | `2>$null` | **不要照抄 `2>/dev/null`** |
| `2>&1` | `2>&1` | 语义一致 |
| `cat x` | `Get-Content x` | |
| `ls x` | `Get-ChildItem x` | |
| `echo "exit=$?"` | `"exit=$LASTEXITCODE"` | `$?` 在 PowerShell 里是布尔 |
| `git ...` | **原样可用** | git 自带自己的 shell 语义 |

> **两条硬规矩**：
> 1. **换 shell 就换整套命令** —— 不要 POSIX 与 PowerShell 混着用。
> 2. **探测结果必须带命令原文与输出**（写进尽调结论）。事后才能判断「当初是不是探错了」。

---

### 1. VCS 与回滚能力

```sh
git rev-parse --show-toplevel 2>&1; echo "exit=$?"
git status --porcelain | head -20
git log --oneline -5 2>&1
```

| 结论 | 影响 |
|---|---|
| 有 git 且是仓库根 | 快照可作为**可选**补充；宪法里「回滚」一节写 git |
| 无 git（exit 128） | **快照是唯一退路** → 必须进硬停清单，每轮动手前打快照 |
| 有 git 但目标目录不在仓库内 | 同上，按无 git 处理 |

> ⚠ 常见陷阱：仓库根有 `.git`，但某个 submodule / vendored 目录自己也有 `.git`。
> 两个都要探，分别记录。

### 2. 有没有外部上游

```sh
cat .gitmodules 2>/dev/null
find . -maxdepth 3 \( -name "upstream*.json" -o -name "*VENDOR*" -o -name "PATCHES*" \) 2>/dev/null
grep -rl "vendored\|@generated\|DO NOT EDIT\|This file is auto-generated" --include="*.md" --include="*.ts" --include="*.py" --include="*.go" . 2>/dev/null | head -20
```

判断口径（**按来源分，不按目录名分**）：

| 来源 | 特征 | 可写性 |
|---|---|---|
| **甲 · 产品本体** | 自己写的、外部发布不会替换它 | 默认可写（档位仍在） |
| **乙 · 外部上游** | 随新版本**整体替换**：submodule、peer 依赖、vendored 库 | 绝对只读；只经**已文档化**的公开面集成 |
| **丙 · 版本耦合的脚手架** | 从模板/fork 继承、与上游版本强耦合：补丁、CI 配置、根 manifest | 只读，需当轮特别授权 |

**甲类里还有一件必做**：找出「升级上游会让哪些工作白做」。凡是**咬住上游具体形状**的待办
（依赖上游的类名/token/未文档化的面/「当前版本某字段恒空」这种版本性质），
要么排在 pin 更新之后，要么把耦合**集中到一处并注释标注上游版本**。

### 3. 真实门禁命令

按语言探（有几个探几个，**不要发明**）：

```sh
# Node / TS
cat package.json | grep -A30 '"scripts"'
# Python
ls pyproject.toml setup.py tox.ini Makefile 2>/dev/null
# Rust / Go
ls Cargo.toml go.mod Makefile 2>/dev/null
# 通用
ls .github/workflows/ .gitlab-ci.yml .circleci/ 2>/dev/null
```

产出：一张**门禁表**，每行是
`门禁名 | 真实命令 | 输出怎么判定通过 | 探测不可得时记什么 | 红了谁修 | 日志落到哪`。

**探不到的写法**：`格式检查 | 不适用 + 原因：本仓库无独立 formatter 配置`。
**绝不**留空行——空行与「查过没有」在事后无法区分，这正是本框架反复强调的纪律。

> **最后两列容易漏，但它们是门禁能不能闭环的关键。**
> 「探测不可得」回答**这次跑不出结果**时记什么（超时 / 无权限 / 上游截断）；
> 「红了谁修」回答门变红之后的下一步动作。**答不出「红了怎么办」的检查项只能做报告级。**
> 只有标准档起要求逐行填；轻量档各写一句总规则即可（见 `core/gates-and-holds.md` §一 档位裁剪）。

### 4. 已有文档体系

```sh
ls AGENTS.md CLAUDE.md CONTRIBUTING.md docs/ 2>/dev/null
find . -maxdepth 2 -name "*.md" -not -path "./node_modules/*" | head -40
# 工作区 vs HEAD：既有治理体系是否"已存在但被删掉/尚未检出"
git -c core.quotepath=false ls-tree -r --name-only HEAD 2>/dev/null \
  | grep -E '^(AGENTS\.md|CLAUDE\.md|docs/|governance/|执行计划/)' | head -20
git status --porcelain 2>/dev/null | awk '{print $1}' | sort | uniq -c
```

### 4.0 **先判「已有治理体系」是否真的不存在**（**这一步不能跳**）

>`ls` 看不到 ≠ 不存在。最危险的形态是：**HEAD 里有一整套跑了 N 轮的治理树，工作区里却已删光**
>（删除未提交 / 换分支 / 解压覆盖）。此时照「新项目」生成，会得到**两套并存的治理树** ——
> 正是 `anti-patterns.md` 反复警告的反模式，而且**没有任何门禁会红**。

**判据**：

| 探测结果 | 含义 | 必须先做的事 |
|---|---|---|
| `ls` 有 `<GOV_ROOT>/`，**或**有「工作范式 / 执行计划 / 治理树」这类治理标记 | 已有治理体系 | 走 **审计模式**（`audit-and-evolve.md`），不重建 |
| `ls` 只有 `AGENTS.md`（或 `CLAUDE.md`），没有治理根 | **只是行业约定的规则文件**，不是治理体系 | 按 §一 继续初始化；宪法段**末尾追加**，绝不覆盖 |
| `ls` 没有，但 `git ls-tree HEAD` 命中 | **已存在但被删/未检出** | **停**，把「HEAD 里有 N 个文件、工作区 0 个」如实报给用户，**由用户裁决**：恢复审计 / 封存重建 / 直接重建 |
| `git status` 里出现成批 `D`（几十上百） | 同上，且删除**未提交** | 同上一行；**不要**`git checkout -- .`「顺手恢复」 |
| 两边都没有 | 真的是新项目 | 按 §一 继续 |

**封存重建时**（用户选了这条路）：先把旧树**完整导出**到**仓库外**
（`git archive` 到 zip），记下条目数 / 字节数 / SHA-256，再建新体系。
**不要在仓库里留旧树的副本** —— 两棵树并存比丢历史更糟。

- **宪法段写到哪，取决于宿主读哪个文件**（见 `templates/_宪法段模板.md` §六）：
  - 只有 `CLAUDE.md` → 写进 `CLAUDE.md`
  - 只有 `AGENTS.md` → 写进 `AGENTS.md`，**并新建 `CLAUDE.md` 写 `@AGENTS.md`**
  - 两者都有 → 写进 `AGENTS.md`，并在 `CLAUDE.md` 补 `@AGENTS.md`
  **绝不两处各写一份正文**（那是双份记录）。记录追加位置的原始行数。
- 已有 `docs/` → 治理根嵌进去（`<GOV_ROOT>/`），**不要另起一棵树**。
- 已有零散的 TODO / ROADMAP / DECISIONS 文件 → 尽调时列出，生成时在 `项目清单/` 里
  给它们**一席之地**（作为历史输入），不要假装它们不存在。

### 5. 规模判定

```sh
# 粗略：源文件数（按语言挑；要行数另用 wc -l 对文件内容统计）
find . \( -name "*.ts" -o -name "*.tsx" \) -not -path "*/node_modules/*" | wc -l
git ls-files | wc -l
```

**档位判据见 `references/tier-selection.md` §一** —— 那是五档的唯一权威表
（微型 / 轻量 / 标准 / 完整 / 重型）。**本文件不复制一张表**，
否则两张表必然漂移（`doc-sync-discipline.md` §一「规则载体的多处同步」）。

**判别顺序：宁可先低一档。** 判不准时取更低的一档，然后在生成件里写明升档信号。

### 6. 协作模式

```sh
ls CODEOWNERS .github/CODEOWNERS CONTRIBUTING.md 2>/dev/null
```

- 单人 → 「特别授权」口径写死为「只有项目所有者本人」。
- 多人 → 需要决定：谁能派发？谁能拍板？走 PR review 还是走派发件？

---

## 二、必问用户（探不到的才问）

问之前先说明**为什么问**——用户答得快，是因为知道答案会改变什么。

1. **哪些目录绝对不许改？**（→ 可写范围表 + 硬停清单）
   - 追一句：**「如果我说『都能改』会怎样？」** 若用户确实说都能改 → 不启用铁律 1/2，
     在生成件里**写明为什么不启用**（而不是硬塞一条无法执行的规则）。
2. **回滚手段是什么？**（→ 快照是否必需）
3. **谁拍板？什么情况下你会亲自发话？**（→ 授权口径）
4. **这套体系里，你最怕发生什么？** —— 这是**开放题，答案决定 anti-patterns 的侧重**。
   常见答案与对应条款：
   - 「怕新会话不知道我在干什么」→ 交接机制、默认阅读顺序、宪法段
   - 「怕改了不该改的」→ 可写范围、硬停清单、当轮授权
   - 「怕计划写了没人执行」→ 状态机、闭环仪式、完成定义
   - 「怕数字对不上」→ 计数唯一真源、文档同步纪律
5. **产物用中文命名还是英文命名？**（→ 目录与文件名；默认中文，跨语区/英文仓库建议英文；对照表见 `naming.md`）
6. **治理根放在哪？**（→ `<GOV_ROOT>` 的值；**默认值见 `SKILL.md` §3.0**，但若 `docs/` 已被产品文档站占用，建议放仓库根的 `governance/`；定义见 `SKILL.md` §3.0）

---

## 三、交付结论的格式

`<GOV_ROOT>/项目清单/尽调结论.md`：

**形态见 `templates/_尽调结论模板.md`** —— 那是唯一权威版（7 节，含执行者/会话、甲乙丙证据列、硬停清单、以及「当前采用的假设」列）。**本文件不复制一份**，否则副本必然落后于模板（`anti-patterns.md` #12「不留双份记录」）。

**最后一行很重要**：把「当前采用的假设」写出来，用户看到后可以一句话推翻。
不写假设 = 让用户在不知情的情况下接受了一个猜测。
