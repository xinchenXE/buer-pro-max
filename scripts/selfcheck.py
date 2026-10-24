#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""buer-pro-max 自检脚本 (selfcheck)

检查的是 **这个 skill 自己**，不是目标项目。

用法:
    python scripts/selfcheck.py            # 人读的报告
    python scripts/selfcheck.py --quiet    # 只输出失败项(供 CI / 门禁门)

退出码: 0 = 全绿, 1 = 有失败项

为什么要有它:
    这个 skill 的全部内容都是文档, 而文档会"静默腐化" —— 计数漂移、目录树与
    实际文件不符、模板里的内部路径被原样抄进目标项目。这些正是
    references/anti-patterns.md 里记录的坑, 只能靠机械检查兜住。

设计约束:
    - 输出**只用 ASCII 标签** —— 中文在 CP936 控制台下会被转坏
      (见 references/core/id-sequences.md 关于代码页的教训)。
    - 不写文件、不改任何东西, 纯只读。
    - 每个门都要**能看见它该看见的那类错** —— 加门后必须做牙齿验证
      (见 references/tool-contracts.md 的「牙齿验证」一节)。
"""

import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FENCE = "`" * 3

MARKER_RE = re.compile(r"【(必选|可选|参考)([^】]*)】")
# 只在本 skill 内成立的路径前缀
INTERNAL_RE = re.compile(r"(?:^|[\s`(])(?:\.\./)*(?:references|templates)/")

# F4 漏洞 1: 字符类必须含中文, 否则 templates/_宪法段模板.md 这类路径永远匹配不到.
#   漏了中文的后果不是报错, 而是**静默隐形** —— 改名不会被发现.
CJK = "一-鿿"
REF_RE = re.compile(
    r"(references/[A-Za-z0-9_./" + CJK + r"-]+\.md"
    r"|templates/[A-Za-z0-9_." + CJK + r"-]+\.md)"
)

# F4 漏洞 3: README 目录树的两个 load-bearing 锚点.
#   改 README §四 时**不要动这两行**, 否则 tree 变空串 -> 顶层六项全报 missing.
TREE_START = "buer-pro-max/"
TREE_END = "★ = "

# F4 漏洞 2: 围栏 toggle 之后, 落在块外的行不应长得像代码/输出.
#   这是对「嵌套围栏被提前闭合」这类结构性损坏的兜底.
LEAKED_LINE_RE = re.compile(
    r"^\s*(\$\s|<输出摘录>|<命令>|exit=|files=|dead=|skipped|\{\s*verdict:)"
)

# F3: 真行号引用. 允许清单只含刻意示例.
LINE_REF_RE = re.compile(
    r"([A-Za-z0-9_./" + CJK + r"\-]+\.md)\s*:\s*(\d{1,4})"
    r"|（\s*L\d{1,4}\s*[–\-~]\s*L?\d{1,4}\s*）"
    r"|（\s*L\d{1,4}\s*）"
)
LINE_REF_ALLOW = {
    "references/tool-contracts.md",  # 刻意示例: 讲「行号会漂」时举的 file.ts:161
}


# 遍历时跳过的目录 —— .git 里的 pack 文件是二进制, 必然含 CRLF 字节,
# 不跳过会让 bom-and-eol 在**全新克隆上必然误报**（本地无 pack 时不显形）。
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def walk_md():
    out = []
    for dp, dn, fs in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fs:
            if f.endswith(".md"):
                rel = os.path.relpath(os.path.join(dp, f), ROOT).replace(os.sep, "/")
                out.append(rel)
    return sorted(out)



def walk_all():
    """遍历所有文件, **跳过 .git 等非内容目录**.

    不跳过的话, `bom-and-eol` 会去读 `.git/objects/**/*.pack` ——
    那是二进制压缩包, 必然含 CRLF 字节, 于是**全新克隆上必然误报**。
    这个洞是在验证推送结果时被真实发现的（本地仓库没有 pack 文件时不显形）。
    """
    out = []
    for dp, dn, fs in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fs:
            rel = os.path.relpath(os.path.join(dp, f), ROOT).replace(os.sep, "/")
            out.append(rel)
    return sorted(out)


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def read_bytes(rel):
    with open(os.path.join(ROOT, rel), "rb") as fh:
        return fh.read()


def _fence_len(line):
    """返回该行作为围栏的反引号长度; 不是围栏则返回 0.

    **必须按长度配对**, 否则外层 ````（4 个）会被内层 ```（3 个）提前闭合 ——
    这正是 _尽调结论模板.md 那个 bug 的形态, 也是「门看不见该看见的错」的典型。
    """
    s = line.strip()
    if not s.startswith("`"):
        return 0
    n = 0
    while n < len(s) and s[n] == "`":
        n += 1
    return n if n >= 3 else 0


def _walk_fences(text):
    """Yield (lineno, line, content_inside) —— 按反引号**长度**配对.

    规则: 一个以 N 个反引号开启的块, 只被 >=N 个反引号的行闭合.
    这样外层 ````（4）里面的 ```（3）不会被误当成闭合 —— 正是
    _尽调结论模板.md 那个 bug 的形态.
    """
    open_len = 0
    for i, line in enumerate(text.split("\n"), 1):
        n = _fence_len(line)
        if open_len == 0:
            if n:
                open_len = n
                yield i, line, False
            else:
                yield i, line, False
        else:
            if n >= open_len:
                open_len = 0
                yield i, line, False
            else:
                yield i, line, True


def in_code_blocks(text):
    """Return list of (lineno, line) that are inside a fenced code block (content lines only)."""
    return [(i, l) for i, l, inside in _walk_fences(text) if inside]


def outside_code_blocks(text):
    """Return list of (lineno, line) that are NOT inside a fenced block."""
    return [(i, l) for i, l, inside in _walk_fences(text) if not inside]


def ascii_safe(s):
    """控制台可能是 CP936 —— 中文直接 print 会乱码。这里统一转成 ASCII 安全形式。"""
    return str(s).encode("ascii", "backslashreplace").decode("ascii")


class Report(object):
    def __init__(self):
        self.rows = []          # (ok:bool, name:str, detail:str)
        self.failed = 0

    def add(self, ok, name, detail=""):
        self.rows.append((ok, name, detail))
        if not ok:
            self.failed += 1

    def dump(self, quiet):
        for ok, name, detail in self.rows:
            if quiet and ok:
                continue
            tag = "PASS" if ok else "FAIL"
            print("[%s] %-34s %s" % (tag, name, ascii_safe(detail)))
        print("")
        print("total=%d failed=%d" % (len(self.rows), self.failed))


# ---------------------------------------------------------------- gates

def check_fences(md, rep):
    """围栏配对(按长度) + 块外不得残留代码/输出形态的行（F4 漏洞 2）."""
    unbalanced = []
    leaked = []
    for f in md:
        text = read(f)
        # 配对检查: 走完后没有未闭合的块
        open_len = 0
        for line in text.split("\n"):
            n = _fence_len(line)
            if open_len == 0:
                if n:
                    open_len = n
            elif n >= open_len:
                open_len = 0
        if open_len != 0:
            unbalanced.append(f)
        for lineno, line in outside_code_blocks(text):
            if LEAKED_LINE_RE.match(line):
                leaked.append("%s:%d" % (f, lineno))
    ok = not unbalanced and not leaked
    rep.add(ok, "fence-pairing",
            "unbalanced=%s leaked_outside=%d %s" % (
                unbalanced or "none", len(leaked), leaked[:8] if leaked else ""))


def check_internal_dead_links(md, rep):
    """模板的生成块里, 不以 < 开头的内部路径 -> 会被原样抄进目标项目."""
    bad = []
    for f in md:
        if not f.startswith("templates/"):
            continue
        for lineno, line in in_code_blocks(read(f)):
            if INTERNAL_RE.search(line) and not line.strip().startswith("<"):
                bad.append("%s:%d" % (f, lineno))
    rep.add(not bad, "template-dead-links", "count=%d %s" % (len(bad), bad or ""))


def check_path_refs(md, rep):
    """任何 md 里引用的 references/xxx.md 或 templates/xxx.md 必须真实存在.

    每个门的 detail 必须能区分「查了 0 个」与「0 个坏的」—— 因此同时报总引用数.
    """
    bad = []
    total = 0
    for f in md:
        for fname in set(REF_RE.findall(read(f))):
            total += 1
            if not os.path.exists(os.path.join(ROOT, fname)):
                bad.append("%s -> %s" % (f, fname))
    rep.add(not bad, "path-refs-exist",
            "checked=%d bad=%d %s" % (total, len(bad), bad or ""))


def check_orphans(md, rep):
    """除 README/SKILL 外, 每个文件都应至少被另一个文件按文件名提到."""
    bad = []
    corpus = {f: read(f) for f in md}
    for f in md:
        if f in ("README.md", "SKILL.md"):
            continue
        base = os.path.basename(f)
        others = [g for g in md if g != f and base in corpus[g]]
        if not others:
            bad.append(f)
    rep.add(not bad, "orphan-files", "count=%d %s" % (len(bad), bad or ""))


def _tree_text(readme):
    """取 README §四 目录树的**围栏块正文**.

    不能用 `readme.find("buer-pro-max/")` —— §一 安装说明里的
    `cp -r buer-pro-max ~/.claude/skills/` 也含这个子串, 会让切片从一半正文开始,
    反向核对(ghost)就会把正文里的 `AGENTS.md` / `NEXT.md` 当成幽灵条目.
    → 改为: 找到**以 `buer-pro-max/` 开头的行**所在的围栏块, 切到该块闭合围栏为止.
    """
    lines = readme.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.strip() == TREE_START:
            start = i
            break
    if start is None:
        return ""
    # 向上找开启围栏
    head = None
    for j in range(start, -1, -1):
        if lines[j].strip().startswith(FENCE):
            head = j
            break
    if head is None:
        return ""
    # 向下找闭合围栏
    tail = None
    for k in range(start + 1, len(lines)):
        if lines[k].strip().startswith(FENCE):
            tail = k
            break
    if tail is None:
        return ""
    return "\n".join(lines[head:tail + 1])


def _tree_entries(tree):
    """从目录树围栏块里取出**条目名**(├── / └── 之后的那个名字).

    不能对整块跑 `\\w+.md` —— 说明文字里也会提到 `AGENTS.md` / `NEXT.md`
    (如「← ★ 写进 AGENTS.md 的那一段」), 那是描述不是条目, 算进 ghost 会误报.
    """
    names = set()
    for line in tree.split("\n"):
        if "──" not in line:
            continue
        m = re.search(r"──\s+([A-Za-z0-9_" + CJK + r"\-]+(?:\.md|/)?)(?:\s|$)", line)
        if m and m.group(1):
            name = m.group(1)
            # 无扩展名且非目录的, 视为文件(如 LICENSE)
            names.add(name)
    return names


def check_tree_vs_files(md, rep):
    """README 目录树 ↔ 实际文件, **双向**核对(顶层 + references + templates).

    双向 = 树里列的必须存在, 实际有的必须在树里 —— 单向只能抓到一类错误.
    """
    tree = _tree_text(read("README.md"))
    entries = _tree_entries(tree)

    top = {"SKILL.md", "README.md", "LICENSE", "references/", "templates/", "scripts/"}
    missing_top = sorted(t for t in top if t not in entries)

    refs = [os.path.basename(f) for f in md if f.startswith("references/")]
    tpls = [os.path.basename(f) for f in md if f.startswith("templates/")]

    missing_in_tree = sorted([r for r in refs if r not in entries] +
                             [t for t in tpls if t not in entries])

    # 反向: 树里作为**条目**出现的 .md 必须真实存在
    actual_names = set(os.path.basename(x) for x in md)
    ghost = sorted(n for n in entries
                   if n.endswith(".md") and n not in actual_names
                   and n not in ("SKILL.md", "README.md"))

    ok = not missing_top and not missing_in_tree and not ghost
    rep.add(ok, "readme-tree",
            "missing_top=%s missing_in_tree=%s ghost_in_tree=%s" % (
                missing_top or "none", missing_in_tree or "none", ghost or "none"))


def check_md_files(md, rep):
    """md 总数必须等于「2 个根文件 + 树里列的 references + 树里列的 templates」.

    **不硬编码 39** —— 硬编码会让每加一个文件就要改两处, 正是这 skill 自己
    反对的「多处同步」负担. 期望值从 README 目录树推导(树本身由 readme-tree 门校验).

    只认**树条目行**(以 ├── / └── 开头)里的 .md, 不认「← 说明文字」里提到的
    `AGENTS.md` / `NEXT.md` —— 那些是描述, 不是条目.
    """
    tree = _tree_text(read("README.md"))
    entries = _tree_entries(tree)
    ok = len(md) == len([n for n in entries if n.endswith(".md")])
    rep.add(ok, "md-files",
            "actual=%d expected_from_tree=%d" % (
                len(md), len([n for n in entries if n.endswith(".md")])))


def check_count_claims(md, rep):
    """文档里写死的计数必须与机械重算的值一致(「计数漂移」门).

    只查**可独立重算**的三个量. **不查 selfcheck 自己的检查项数** ——
    那是自指: 加一个检查项这个数就变, 而它自己也在被检查, 极易写成永远通过的空门.
    """
    readme = read("README.md")
    problems = []

    # 1. 「N 份模板」
    m = re.search(r"(\d+)\s*份模板", readme)
    n_tpl = len([f for f in md if f.startswith("templates/")])
    if m:
        if int(m.group(1)) != n_tpl:
            problems.append("templates claim=%s actual=%d" % (m.group(1), n_tpl))
    else:
        problems.append("templates claim MISSING in README")

    # 2. 「N 条踩过的坑」 (README 里对 anti-patterns 的描述)
    m = re.search(r"(\d+)\s*条踩过的坑", readme)
    ap = read("references/anti-patterns.md")
    n_ap = len(re.findall(r"^### \d+\.", ap, re.M))
    if m:
        if int(m.group(1)) != n_ap:
            problems.append("anti-patterns claim=%s actual=%d" % (m.group(1), n_ap))
    else:
        problems.append("anti-patterns claim MISSING in README")

    # 3. anti-patterns 自身的编号必须 1..N 连续(缺号/重号都是漂移)
    nums = [int(x) for x in re.findall(r"^### (\d+)\.", ap, re.M)]
    if nums != list(range(1, len(nums) + 1)):
        problems.append("anti-patterns numbering not 1..N: %s" % nums)

    rep.add(not problems, "count-claims",
            "templates=%d anti_patterns=%d %s" % (n_tpl, n_ap,
                                                  problems or ""))


def check_version_consistency(rep):
    """frontmatter 的 version 与 README §十 表首行的版本必须一致.

    兼容两种位置: 顶层 `version:` (旧) 与 `metadata:` 下的缩进 `version:` (规范).
    """
    skill = read("SKILL.md")
    m = re.search(r"^\s*version:\s*[\"']?([^\"'\s]+)[\"']?\s*$", skill, re.M)
    ver = m.group(1) if m else None
    readme = read("README.md")
    # P2-13: 取**第一个**版本单元格 -> 新版本行必须插在表首
    m2 = re.search(r"\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|", readme)
    latest = m2.group(1) if m2 else None
    ok = ver is not None and ver == latest
    rep.add(ok, "version-consistency", "skill=%s readme_latest=%s" % (ver, latest))


def check_markers(md, rep):
    """标记语汇必须收敛在约定的形态内.

    允许:
        【必选】  【必选 · 触发：X】  【必选 · 标准档起】
        【可选 · 触发：X】  【可选 · 推荐】  【可选 · 推荐 —— ...】
        【参考】  【参考 · X】
    拒绝: 「必选 —— X」「必选（标准档起）」等非约定形态.
    """
    counts = {"必选": 0, "可选": 0, "参考": 0}
    vocab = {}
    bad = []
    for f in md:
        for kind, rest in MARKER_RE.findall(read(f)):
            counts[kind] += 1
            vocab[kind + rest] = vocab.get(kind + rest, 0) + 1
            if kind == "必选":
                ok = rest == "" or rest.startswith(" · 触发：") or rest == " · 标准档起"
            elif kind == "可选":
                ok = rest.startswith(" · 触发：") or rest.startswith(" · 推荐")
            else:
                ok = rest == "" or rest.startswith(" · ")
            if not ok:
                bad.append("%s: 【%s%s】" % (f, kind, rest))
    detail = "must=%d optional=%d ref=%d vocab_forms=%d invalid=%d %s" % (
        counts["必选"], counts["可选"], counts["参考"], len(vocab), len(bad), bad[:5] if bad else "")
    rep.add(not bad, "marker-vocabulary", detail)


def check_stale_phrases(md, rep):
    """曾经修过、不应再出现的写法."""
    stale = {
        "【必选 —— ": "old em-dash marker form",
        "触发条件见文件内": "lazy marker",
        "2 目录 + 3 模板": "unverified dir count",
        "8 目录 + 8 模板": "unverified dir count",
        "只装两样东西": "stale tier claim",
    }
    bad = []
    for f in md:
        t = read(f)
        for k, why in stale.items():
            if k in t:
                bad.append("%s: %s (%s)" % (f, k, why))
    rep.add(not bad, "stale-phrases", "count=%d %s" % (len(bad), bad or ""))


def check_line_number_refs(md, rep):
    """F3 新门: 全库真行号引用应为 0(允许清单除外).

    这个 skill 自己把「行号会漂」标成【必选】—— 所以它自己不该有行号引用.
    """
    bad = []
    for f in md:
        if f in LINE_REF_ALLOW:
            continue
        for lineno, line in enumerate(read(f).splitlines(), 1):
            if LINE_REF_RE.search(line):
                bad.append("%s:%d" % (f, lineno))
    rep.add(not bad, "line-number-refs", "count=%d %s" % (len(bad), bad or ""))


def check_bom_and_eol(rep):
    """F4 新门 A: 任何文件不得带 BOM; 行尾必须全库统一为 LF."""
    bom, crlf = [], []
    for f in walk_all():
        b = read_bytes(f)
        if b.startswith(b"\xef\xbb\xbf"):
            bom.append(f)
        if b"\r\n" in b:
            crlf.append(f)
    ok = not bom and not crlf
    rep.add(ok, "bom-and-eol",
            "bom=%d crlf=%d %s" % (len(bom), len(crlf), crlf if crlf else ""))


def check_gov_root_literal(md, rep):
    """新门 A: \u6cbb\u7406\u6839\u8def\u5f84\u4e0d\u5f97\u5199\u6b7b.

    `<GOV_ROOT>` \u662f\u552f\u4e00\u5360\u4f4d\u7b26\uff0c\u5b83\u7684\u9ed8\u8ba4\u503c **\u53ea\u80fd\u5728\u4e00\u5904\u5b9a\u4e49**
    \uff08`SKILL.md` \u00a73.0\uff09\u3002\u5176\u4f59\u5730\u65b9\u5199\u5b57\u9762\u91cf = \u4e0d\u53ef\u914d\u7f6e\u3002

    \u4f8b\u5916\u767d\u540d\u5355\uff1a
      - `SKILL.md` \u2014\u2014 \u5b83\u6709 \u00a73.0 \u7684\u5b9a\u4e49\u5757\uff08\u9ed8\u8ba4\u503c\u5c31\u5728\u90a3\u91cc\uff09
      - `README.md` \u2014\u2014 \u5b89\u88c5/\u7528\u6cd5\u793a\u4f8b\uff0c\u9762\u5411\u8bfb\u8005\u7684\u81ea\u7136\u8bed\u8a00
    """
    LITERAL = "docs/governance"
    ALLOW = {"SKILL.md", "README.md"}
    bad = []
    for f in md:
        if f in ALLOW:
            continue
        for i, line in enumerate(read(f).split("\n"), 1):
            if LITERAL in line:
                bad.append("%s:%d" % (f, i))
    rep.add(not bad, "gov-root-literal", "count=%d %s" % (len(bad), bad[:8] if bad else ""))


# \u6863\u4f4d\u6807\u8bb0\u8bed\u6cd5: {\u6807\u51c6\u8d77} {\u5b8c\u6574\u8d77} {\u91cd\u578b} {\u65e0VCS} {\u53ef\u9009\u00b7\u89e6\u53d1} {\u6807\u51c6\u8d77\u00b7\u89e6\u53d1} {\u5b8c\u6574\u8d77\u00b7\u89e6\u53d1} {\u63a8\u8350\u9879}
TIER_MARK_RE = re.compile(r"\{([^{}\n]{1,12})\}")
TIER_MARK_ALLOWED = {
    "\u6807\u51c6\u8d77", "\u5b8c\u6574\u8d77", "\u91cd\u578b", "\u65e0VCS",
    "\u53ef\u9009\u00b7\u89e6\u53d1", "\u6807\u51c6\u8d77\u00b7\u89e6\u53d1",
    "\u5b8c\u6574\u8d77\u00b7\u89e6\u53d1", "\u63a8\u8350\u9879",
}


def check_tree_tier_markers(md, rep):
    """\u65b0\u95e8 B: \u751f\u6210\u6811\u7684\u6863\u4f4d\u6807\u8bb0\u5408\u6cd5 + \u5b50\u9879\u7ee7\u627f\u7236\u5bb9\u5668.

    2026-10-24 \u7aef\u5230\u7aef\u8bd5\u8dd1\u62ab\u9732\u4e24\u4e2a\u5c42\u6b21\u7684\u9519\uff1a
      1. `\u4e22\u5f03\u8ba1\u5212/` `\u6267\u884c\u504f\u5dee/` `\u64cd\u4f5c\u8bb0\u5f55/` \u753b\u8fdb\u4e86\u6811\u5374\u6ca1\u6807\u6863\u4f4d
      2. `\u6267\u884c\u504f\u5dee/ {\u5b8c\u6574\u8d77}` \u7684**\u5b50\u9879\u6ca1\u6709\u7ee7\u627f\u7236\u7ea7\u6807\u8bb0**\uff0c
         \u6309\u6811\u751f\u6210\u4ecd\u4f1a\u8bef\u5efa\u6574\u68f5\u504f\u5dee\u5b50\u6811

    \u7b2c 2 \u7c7b\u662f\u300c\u95e8\u770b\u4e0d\u89c1\u5b83\u8be5\u770b\u89c1\u7684\u9519\u300d\u7684\u53c8\u4e00\u5b9e\u4f8b \u2014\u2014 \u4e0e\u5d4c\u5957\u56f4\u680f\u540c\u578b\u3002
    """
    gt = read("references/gen-tree.md")
    bad = []
    n_marks = 0

    # \u89e3\u6790\u6811\u56f4\u680f\u5757, \u8ddf\u8e2a\u6bcf\u4e00\u5c42\u7684\u751f\u6548\u6807\u8bb0
    in_tree = False
    stack = []          # [(indent_len, effective_mark_or_None, name)]
    for i, line in enumerate(gt.split("\n"), 1):
        if line.strip().startswith(FENCE):
            in_tree = not in_tree
            continue
        if not in_tree:
            continue

        mk = TIER_MARK_RE.search(line)
        mark = mk.group(1) if mk else None
        if mark is not None:
            n_marks += 1
            if mark not in TIER_MARK_ALLOWED:
                bad.append("references/gen-tree.md:%d unknown mark {%s}" % (i, mark))
                continue

        # \u53d6\u6761\u76ee\u540d
        m = re.search(r"[\u251c\u2514]\u2500\u2500\s+([^\s\u2190]+)", line)
        if not m:
            continue
        name = m.group(1)
        indent = line.find("\u251c") if "\u251c" in line else line.find("\u2514")
        if indent < 0:
            indent = len(line) - len(line.lstrip())

        # \u5f39\u51fa\u6bd4\u5f53\u524d\u66f4\u6df1\u6216\u540c\u7ea7\u7684\u6808\u9879
        while stack and stack[-1][0] >= indent:
            stack.pop()

        # \u7236\u7ea7\u751f\u6548\u6807\u8bb0 = \u6808\u9876
        inherited = stack[-1][1] if stack else None
        effective = mark if mark is not None else inherited

        # \u5982\u679c\u672c\u884c\u662f\u4e00\u4e2a\u5bb9\u5668(\u4ee5 / \u7ed3\u5c3e)\u4e14\u6709\u951a\u5b9a\u6863\u4f4d\u95e8\u69db, \u4f46\u5b50\u9879\u65e0\u6807\u8bb0 -> \u62a5
        stack.append((indent, effective, name))

    # \u5fc5\u8981\u6027\uff1a\u5b9a\u4e49\u4e86\u6807\u8bb0\u8bed\u6cd5\u5c31\u4e0d\u80fd\u4e00\u4e2a\u90fd\u6ca1\u6709
    if n_marks < 8:
        bad.append("references/gen-tree.md: only %d tier marks (expected >= 8)" % n_marks)

    rep.add(not bad, "tree-tier-markers", "marks=%d count=%d %s" % (
        n_marks, len(bad), bad[:8] if bad else ""))


def check_tree_subtree_inherit(md, rep):
    """\u65b0\u95e8 C: \u6709\u6863\u4f4d\u95e8\u69db\u7684\u5bb9\u5668, \u5176\u5b50\u9879\u5fc5\u987b\u663e\u5f0f\u7ee7\u627f\u8be5\u6807\u8bb0.

    \u5224\u636e\uff1a\u7236\u884c\u5e26 `{X}`\uff0c\u5219\u6240\u6709\u7f29\u8fdb\u66f4\u6df1\u7684\u5b50\u884c\u90fd\u5fc5\u987b\u5e26 `{X}`
    \uff08\u663e\u5f0f\u5199\u51fa\u6765\uff0c\u4e0d\u9760\u9690\u5f0f\u7ee7\u627f \u2014\u2014 \u56e0\u4e3a\u751f\u6210\u8005\u4f1a\u9010\u884c\u8bfb\uff09\u3002
    """
    gt = read("references/gen-tree.md")
    bad = []
    in_tree = False
    parent = None   # (indent, mark, name)
    for i, line in enumerate(gt.split("\n"), 1):
        if line.strip().startswith(FENCE):
            in_tree = not in_tree
            parent = None
            continue
        if not in_tree or "\u2500\u2500" not in line:
            continue
        mk = TIER_MARK_RE.search(line)
        mark = mk.group(1) if mk else None
        indent = line.find("\u251c", 0, 80)
        if indent < 0:
            indent = line.find("\u2514", 0, 80)
        if indent < 0:
            continue

        if parent is not None:
            p_indent, p_mark, p_name = parent
            if indent > p_indent:
                # 父带标记 -> 子必须带同一个
                if p_mark is not None and mark != p_mark:
                    bad.append("references/gen-tree.md:%d under {%s} missing/inherited" % (i, p_mark))
                # 反向: 子带标记 -> 父必须带（否则父的档位不明，子标了也没用）
                elif p_mark is None and mark is not None:
                    bad.append("references/gen-tree.md:%d has {%s} but parent has none" % (i, mark))
        parent = (indent, mark, line)

    rep.add(not bad, "tree-subtree-inherit", "count=%d %s" % (len(bad), bad[:8] if bad else ""))


def main():
    quiet = "--quiet" in sys.argv
    md = walk_md()
    rep = Report()

    check_fences(md, rep)
    check_internal_dead_links(md, rep)
    check_path_refs(md, rep)
    check_orphans(md, rep)
    check_tree_vs_files(md, rep)
    check_md_files(md, rep)
    check_count_claims(md, rep)
    check_version_consistency(rep)
    check_markers(md, rep)
    check_stale_phrases(md, rep)
    check_line_number_refs(md, rep)
    check_bom_and_eol(rep)
    check_gov_root_literal(md, rep)
    check_tree_tier_markers(md, rep)
    check_tree_subtree_inherit(md, rep)

    rep.dump(quiet)
    return 0 if rep.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
