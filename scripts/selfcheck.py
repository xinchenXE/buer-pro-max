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
#
# 覆盖范围只有两种: `xxx.md:NNN` 与 `（LNN）` / `（LNN–LNN）`.
# **代码文件的 `file.ts:161` 不在扫描面内** —— 扩到这里会让行号漂移的噪音
# 淹没真问题; 代码行号靠 doc-sync-discipline §四 的纪律兜. 这一句必须与
# references/tool-contracts.md §二「局限」保持一致.
#
# 裸层名 `（L1）` / `（L0–L5）` 不是行号: 要求 L 后**至少两位数字**,
# 否则任何写「L1/L2」的文档都会误红 (2026-10-25 实测). 两位起仍能覆盖
# L10..L9999 这类真引用.
LINE_REF_RE = re.compile(
    r"([A-Za-z0-9_./" + CJK + r"\-]+\.md)\s*:\s*(\d{1,4})"
    r"|（\s*L\d{2,4}\s*[–\-~]\s*L?\d{2,4}\s*）"
    r"|（\s*L\d{2,4}\s*）"
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
    # 0 个受检对象 != 0 个坏的 (anti-patterns #26 防 2).
    # 语料里一个引用都没解析出来, 只能是扫描面/正则坏了 —— 必须报错,
    # 不能把「查了 0 个」当成「0 个都有问题」而 PASS.
    if total == 0:
        bad.append("NO applicable references matched (scan root empty or regex broken?)")
    rep.add(not bad, "path-refs-exist",
            "checked=%d bad=%d %s" % (total, len(bad), bad or ""))


def check_orphans(md, rep):
    """除 README/SKILL 外, 每个文件都应至少被另一个文件按**唯一可识别的名字**提到.

    判据用**性质**: 名字只有在全库唯一时才能单独指代文件; 重名时必须写路径
    (`templates/naming.md`), 否则就是「谁都能被它指」的假绿 —— 与 #21 同型.

    README 的**目录树围栏块**不算「被引用」: readme-tree 门强制每个文件都出现在
    树里, 若把它算进语料, 本门就恒真命中、永远不会红.
    """
    bad = []
    corpus = {f: read(f) for f in md}
    if "README.md" in corpus:
        keep, inside = [], False
        for ln in corpus["README.md"].split(chr(10)):
            if ln.strip().startswith(FENCE):
                inside = not inside
                continue
            if not inside:
                keep.append(ln)
        corpus["README.md"] = chr(10).join(keep)

    from collections import Counter
    base_count = Counter(os.path.basename(f) for f in md)
    stem_of = lambda f: os.path.basename(f)[:-3] if f.endswith(".md") else os.path.basename(f)
    stem_count = Counter(stem_of(f) for f in md)

    candidates = 0
    for f in md:
        if f in ("README.md", "SKILL.md"):
            continue
        candidates += 1
        base, stem = os.path.basename(f), stem_of(f)
        pats = [re.compile(r"(?<![\w-])" + re.escape(f) + r"(?![\w-])")]
        # 只有全库唯一的 basename / stem 才允许单独指代; 重名必须写路径
        if base_count[base] == 1:
            pats.append(re.compile(r"(?<![\w-])" + re.escape(base) + r"(?![\w-])"))
        if stem_count[stem] == 1:
            pats.append(re.compile(r"(?<![\w-])" + re.escape(stem) + r"(?![\w-])"))
        others = [g for g in md if g != f and any(p.search(corpus[g]) for p in pats)]
        if not others:
            bad.append(f)
    # 0 个候选 != 0 个坏的
    if candidates == 0:
        bad.append("NO candidate files to scan (only README/SKILL in corpus?)")
    rep.add(not bad, "orphan-files", "candidates=%d count=%d %s" % (
        candidates, len(bad), bad or ""))



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

    两类数字分开处理, 这是本门最重要的设计决定:

    1. **artifact count** —— 能从文件树/条目机械重算 (模板数 / anti-pattern 条数).
       自动算, 不需要登记;
    2. **concept count** —— 由治理设计决定 (五档 / 六条提问 / 四条核心约束 ...).
       不能从文件推导, 只能进 CONCEPT_SOURCES 白名单, 并声明权威期望值.
    3. **narrative count** —— 「三个问题」「有一次」这类叙述, **永不扫描**.
       无差别扫 `N 个/条` 会产出几百条误报, 把真声明淹掉.

    不查 selfcheck 自己的门数 —— 那是自指, 加一门数字就变, 极易写成空门.
    """
    readme = read("README.md")
    problems = []
    # 冻结的修订表行 (旧版本的历史表述) 不参与计数校验
    FROZEN_ROW = re.compile(r"^\|\s*\*\*\d+\.\d+\.\d+\*\*\s*\|")

    def _count_hits(pattern):
        """全库(冻结行除外/围栏内除外)扫描某个构件计数, 返回 [(file,lineno,value)]."""
        out = []
        for f in md:
            text = read(f)
            # 构件计数**不跳过围栏**: README 的目录树本身就写在围栏里,
            # 「23 份模板 / 29 条踩过的坑」正是在那儿声明的.
            # 只跳过冻结的修订表行 (那是历史口径).
            for i, line in enumerate(text.split(chr(10)), 1):
                if FROZEN_ROW.match(line.strip()):
                    continue
                for m in re.finditer(pattern, line):
                    out.append((f, i, m.group(1)))
        return out

    # ---------- artifact counts ----------
    # **全库**校验全部命中, 不只查 README 的第一处 ——
    # 否则同一个数字在第二处被改错（或在别的文件里写错）也发现不了。
    # 1. 「N 份模板」
    n_tpl = len([f for f in md if f.startswith("templates/")])
    hits = _count_hits(r"(\d+)\s*份模板")
    if not hits:
        problems.append("templates claim MISSING")
    for f, i, h in hits:
        if int(h) != n_tpl:
            problems.append("%s:%d templates claim=%s actual=%d" % (f, i, h, n_tpl))

    # 2. 「N 条踩过的坑」
    ap = read("references/anti-patterns.md")
    n_ap = len(re.findall(r"^### \d+\.", ap, re.M))
    ap_hits = _count_hits(r"(\d+)\s*条踩过的坑")
    if not ap_hits:
        problems.append("anti-patterns claim MISSING")
    for f, i, h in ap_hits:
        if int(h) != n_ap:
            problems.append("%s:%d anti-patterns claim=%s actual=%d" % (f, i, h, n_ap))

    # 3. anti-patterns 自身的编号必须 1..N 连续(缺号/重号都是漂移)
    nums = [int(x) for x in re.findall(r"^### (\d+)\.", ap, re.M)]
    if nums != list(range(1, len(nums) + 1)):
        problems.append("anti-patterns numbering not 1..N: %s" % nums)

    # ---------- concept counts (受监督集合) ----------
    # 每条: (正则, 期望值, 说明). 正则必须只匹配**声明**, 不能匹配叙述.
    # 新增概念计数 -> 同轮登记到这里 (references/self-check.md 有对应勾选项).
    # 数字形态同时接受中文与阿拉伯 (「六条」与「6 条」等价).
    CJK_DIGIT = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6,
                 "七": 7, "八": 8, "九": 9}

    def _cjk_num(s):
        """多位中文数字 -> int. 支持 十 / 十二 / 二十 / 二十三 / 一百."""
        if s.isdigit():
            return int(s)
        if "百" in s:
            a, _, b = s.partition("百")
            return CJK_DIGIT.get(a, 1) * 100 + (_cjk_num(b) if b else 0)
        if "十" in s:
            a, _, b = s.partition("十")
            return (CJK_DIGIT.get(a, 1) * 10) + (CJK_DIGIT.get(b, 0) if b else 0)
        if len(s) == 1 and s in CJK_DIGIT:
            return CJK_DIGIT[s]
        return None
    NUM = r"[一二三四五六七八九十0-9]"
    concept_scanned = 0
    suppressed = []
    # **冻结面不参与**: README §十 修订表是历史记录, 引用的是当年口径,
    # 改它等于篡改账本 (anti-patterns #13). 用行形态识别, 不按节号硬编码.
    FROZEN_LINE_RE = re.compile(r"^\|\s*\*\*\d+\.\d+\.\d+\*\*\s*\|")
    for f in md:
        text = read(f)
        in_fence = {i for i, _ in in_code_blocks(text)}
        for i, line in enumerate(text.split("\n"), 1):
            if line.count("count:off") and re.search(r"<!--\s*count:off\s*:.*?-->\s*$", line):
                suppressed.append("%s:%d" % (f, i))
                continue
            if FROZEN_LINE_RE.match(line.strip()):
                continue
            # 代码围栏里的计数是**示例**, 不是声明 (例如契约里的输出样例)
            if i in in_fence:
                continue
            # 序数引用 / 变化叙述不是「共有 N 条」的声明
            if CONCEPT_NARRATIVE_RE.search(line):
                continue
            for pat, want, label in CONCEPT_SOURCES:
                for mm in re.finditer(pat, line):
                    concept_scanned += 1
                    got = mm.group(1)
                    val = _cjk_num(got)
                    if val is None:
                        problems.append("%s:%d %s unparsable=%r" % (f, i, label, got))
                        continue
                    if val != want:
                        problems.append("%s:%d %s claim=%s expected=%d" % (
                            f, i, label, got, want))
    # 登记的每条概念都必须在**代码围栏外**至少出现一次, 否则是过期登记
    for pat, want, label in CONCEPT_SOURCES:
        found = False
        for f in md:
            text = read(f)
            in_fence = {i for i, _ in in_code_blocks(text)}
            for i, line in enumerate(text.split("\n"), 1):
                if i not in in_fence and re.search(pat, line):
                    found = True
                    break
            if found:
                break
        if not found:
            problems.append("registered concept never appears (outside fences): %s" % label)

    rep.add(not problems, "count-claims",
            "templates=%d anti_patterns=%d concept_scanned=%d suppressed=%d %s" % (
                n_tpl, n_ap, concept_scanned, len(suppressed), problems or ""))
    if suppressed:
        # 抑制标记必须可见: 打印位置, 不能只打印总数 (否则会变成藏污纳垢处)
        print("  count-claims suppressed at: %s" % ascii_safe(", ".join(suppressed)))


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
    if sum(counts.values()) == 0:
        bad.append("NO markers found (marker regex broken or docs unmarked?)")
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
            # URL 里的 `docs/file.md:42` 是网址, 不是本仓库的行号引用
            if "://" in line:
                continue
            if LINE_REF_RE.search(line):
                bad.append("%s:%d" % (f, lineno))
    rep.add(not bad, "line-number-refs", "count=%d %s" % (len(bad), bad or ""))


def _table_cells(line):
    """数一条表格行有几列.

    不算分隔符的 `|`：行内代码里的（`` `a|b` ``）与被反斜杠转义的（`a \\| b`）。
    """
    masked = re.sub(r"`[^`]*`", lambda m: m.group(0).replace("|", "\x00"), line)
    masked = re.sub(r"\\\|", "\x00", masked)
    return len(masked.strip().strip("|").split("|"))


def _is_separator(line):
    """表头分隔行: 只含 | - : 与空白, 且至少有一个 - ."""
    s = line.strip()
    return s.startswith("|") and "-" in s and re.match(r"^\|[\s|:\-]+\|$", s) is not None


def check_table_shape(md, rep):
    """每张 markdown 表都必须是「表头 + 分隔行 + 同列数数据行」.

    2026-10-25 实测事故: 在 README §十 的修订表插入新行时多留了一个空行,
    于是表格从中间断开 —— 渲染出来后半截没有表头, 但**没有任何门能发现**
    (`fence-pairing` 只看代码围栏, `md-files` 只看文件数).

    判据用**性质**, 不认具体表:
      1. 每个连续表格块的**第二行必须是分隔行** (否则就是被空行截断的半截表);
      2. 同一块内所有行的列数必须相等 (行内代码里的 `|` 先屏蔽).
    代码围栏内的表格不算 —— 那是示例.
    """
    bad = []
    tables = 0
    for f in md:
        text = read(f)
        # 模板整体包在 ```markdown 围栏里, 其表格仍必须校验;
        # 其它文件里的围栏是「示例」, 不参与.
        inside = set() if f.startswith("templates/") else {i for i, _ in in_code_blocks(text)}
        lines = text.split("\n")
        block = []                      # [(lineno, line)]
        def flush():
            nonlocal tables
            if not block:
                return
            tables += 1
            start = block[0][0]
            if len(block) < 2 or not _is_separator(block[1][1]):
                bad.append("%s:%d table without header separator" % (f, start))
            widths = set(_table_cells(l) for _, l in block)
            if len(widths) > 1:
                bad.append("%s:%d column count mismatch %s" % (f, start, sorted(widths)))
        for i, line in enumerate(lines, 1):
            if i in inside:
                if block:
                    flush(); block = []
                continue
            s = line.strip()
            is_row = s.startswith("|") and s.endswith("|") and s.count("|") >= 3
            if is_row:
                block.append((i, line))
            else:
                flush(); block = []
        flush()
    if tables == 0:
        bad.append("NO tables found (table detector broken?)")
    rep.add(not bad, "table-shape",
            "tables=%d bad=%d %s" % (tables, len(bad), bad[:6] if bad else ""))


TEXT_EXT = {".md", ".py", ".txt", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ""}
BOMS = (bytes([0xEF, 0xBB, 0xBF]), bytes([0xFF, 0xFE]), bytes([0xFE, 0xFF]))
CRLF_BYTES = bytes([0x0D, 0x0A])


def check_bom_and_eol(rep):
    """F4 new gate A: text files must not carry a BOM; line endings must be LF."""
    bom, crlf = [], []
    for f in walk_all():
        if os.path.splitext(f)[1].lower() not in TEXT_EXT:
            continue
        data = read_bytes(f)
        if any(data.startswith(mark) for mark in BOMS):
            bom.append(f)
        if CRLF_BYTES in data:
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
    """\u65b0\u95e8 C: \u5bb9\u5668\u7684\u5168\u90e8\u540e\u4ee3\u5fc5\u987b\u663e\u5f0f\u7ee7\u627f\u8be5\u5bb9\u5668\u7684\u6863\u4f4d\u6807\u8bb0.

    **2026-10-24 \u4fee**\uff1a\u65e7\u5b9e\u73b0\u53ea\u6bd4\u8f83\u76f8\u90bb\u884c\uff0c\u4e8e\u662f\u53ea\u80fd\u6293\u5230\u6bcf\u4e2a\u5bb9\u5668\u7684**\u7b2c\u4e00\u4e2a**\u5b50\u9879\u3002
    \u7b2c 2 \u4e2a\u8d77\u7684\u5144\u5f1f\u5168\u90e8\u6f0f\u68c0\u3002\u73b0\u6539\u7528**\u7f29\u8fdb\u6808**\uff0c\u53d6\u6700\u8fd1\u7684\u771f\u6b63\u7956\u5148\u3002
    """
    gt = read("references/gen-tree.md")
    bad = []
    in_tree = False
    stack = []      # [(indent, mark, name)]

    for i, line in enumerate(gt.split("\n"), 1):
        if line.strip().startswith(FENCE):
            in_tree = not in_tree
            stack = []
            continue
        if not in_tree or "\u2500\u2500" not in line:
            continue
        mk = TIER_MARK_RE.search(line)
        mark = mk.group(1) if mk else None

        indent = line.find("\u251c")
        if indent < 0:
            indent = line.find("\u2514")
        if indent < 0:
            continue

        # \u5f39\u51fa\u6240\u6709\u7f29\u8fdb >= \u5f53\u524d\u7684\u6808\u9879 -> \u6808\u9876\u5c31\u662f\u771f\u6b63\u7956\u5148
        while stack and stack[-1][0] >= indent:
            stack.pop()

        if stack:
            p_indent, p_mark, p_name = stack[-1]
            if p_mark is not None and mark != p_mark:
                bad.append("references/gen-tree.md:%d under {%s} (from %s)" % (i, p_mark, p_name))
            elif p_mark is None and mark is not None:
                # \u5b50\u5e26\u6807\u8bb0\u4f46\u7956\u5148\u65e0\u6807\u8bb0\u3002
                # **\u6839\u5bb9\u5668\u8c41\u514d**\uff1a<GOV_ROOT>/ \u4e0e <\u9879\u76ee\u6839>/ \u672c\u8eab\u4e0d\u5c5e\u4e8e\u4efb\u4f55\u6863\u4f4d\uff0c
                # \u5b83\u7684\u5b50\u9879\u5404\u81ea\u5e26\u6863\u4f4d\u662f\u6b63\u786e\u7684\u3002
                is_root = ('<GOV_ROOT>' in p_name) or ('\u9879\u76ee\u6839' in p_name)
                if not is_root:
                    bad.append("references/gen-tree.md:%d has {%s} but ancestor %s has none" % (i, mark, p_name))

        stack.append((indent, mark, line.strip()[:40]))

    rep.add(not bad, "tree-subtree-inherit", "count=%d %s" % (len(bad), bad[:8] if bad else ""))


def check_tier_table_consistency(md, rep):
    """生成树的档位标记必须与 tier-selection.md §一 的权威表一致.

    **2026-10-24 复审修**：旧版 docstring 声称「与权威表一致」，
    但代码**从未读过 `references/tier-selection.md`**，只硬编码了 5 条；
    且 `if r:` 在容器行缺失时**静默通过**，`if legend:` 在图例解析失败时
    整条规则跳过。三个坑同时存在，这道门很容易失效。

    现在：从权威表的「计划容器」行**反推**出每个容器的起档，
    再逐个与 gen-tree 的标记比对。任一容器行缺失、图例为空、或标记不符都报错。
    """
    ts = read("references/tier-selection.md")
    gt = read("references/gen-tree.md")
    bad = []

    # --- 从权威表反推起档 ---
    tiers = ["微型", "轻量", "标准", "完整", "重型"]
    mark_of = {"微型": None, "轻量": None, "标准": "标准起",
               "完整": "完整起", "重型": "重型"}
    row = None
    for line in ts.split("\n"):
        if line.startswith("| **计划容器**"):
            row = line
            break
    expected = {}
    if row is None:
        bad.append("tier-selection.md: 找不到「**计划容器**」行")
    else:
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        # cells[0] = 「**计划容器**」, 然后五个档位
        # 容器名 -> 权威表里的说法（必须先匹配「归档文档」再匹配「归档」）
        for cname, needle in (("活跃计划", "活跃"), ("归档文档", "归档文档"),
                              ("归档计划", "归档"), ("休眠计划", "休眠"),
                              ("丢弃计划", "丢弃")):
            for idx in range(len(tiers) - 1, -1, -1):
                cell = cells[idx + 1] if idx + 1 < len(cells) else ""
                # 「归档文档」里也含「归档」，先把它抹掉再判断「归档」
                probe = cell.replace("归档文档", "") if needle == "归档" else cell
                if needle in probe and "—" not in cell:
                    expected[cname] = mark_of[tiers[idx]]
                    break

    # --- 解析 gen-tree 的树行 ---
    rows = []
    in_tree = False
    for i, line in enumerate(gt.split("\n"), 1):
        if line.strip().startswith(FENCE):
            in_tree = not in_tree
            continue
        if in_tree and "──" in line:
            mk = TIER_MARK_RE.search(line)
            rows.append((i, line, mk.group(1) if mk else None))

    if not rows:
        bad.append("gen-tree.md: 树行解析为空")

    def find_row(sub):
        for i, line, mk in rows:
            if sub in line:
                return i, line, mk
        return None

    # --- 存在性 + 值精确比对 ---
    for cname, want in expected.items():
        needle = cname + "/"
        r = find_row(needle)
        if r is None:
            bad.append("gen-tree.md: 缺少容器行 %s" % needle)
            continue
        if r[2] != want:
            bad.append("gen-tree.md:%d %s mark={%s} but tier table says {%s}" % (
                r[0], needle, r[2], want))

    # --- 两条特殊硬约束 ---
    r = find_row("AGENTS.md")
    if r and r[2] == "标准起":
        bad.append("gen-tree.md:%d AGENTS.md must NOT be standard-tier-only" % r[0])
    r = find_row("缓存/")
    if r and r[2] and r[2].startswith("标准"):
        bad.append("gen-tree.md:%d cache must not be standard-tier-only" % r[0])

    # --- 图例：空集必须报错，不能静默跳过 ---
    legend = set()
    in_legend = False
    for line in gt.split("\n"):
        if "标记" in line and "怎么读" in line:
            in_legend = True
            continue
        if "标记" in line and ("含义" in line or "| 标记 |" in line):
            in_legend = True
            continue
        if in_legend:
            if line.startswith("**") or line.startswith("---"):
                break
            for m in re.findall(r"`\{([^{}`]+)\}`", line):
                legend.add(m.strip())
    if not legend:
        bad.append("gen-tree.md: 图例表解析为空（标题被改名？）")
    for i, line, mk in rows:
        if mk and mk not in legend:
            bad.append("gen-tree.md:%d mark {%s} missing from legend" % (i, mk))

    rep.add(not bad, "tier-table-consistency",
            "checked=%d bad=%d %s" % (len(expected), len(bad), bad[:6] if bad else ""))


def check_container_readme_sections(md, rep):
    """每个容器 README 模板都必须写「不在这里放什么」.

    **2026-10-24 修**: 旧版匹配到 0 个模板时 `bad` 为空直接 PASS,
    无法区分「查了 0 个」与「0 个坏的」。现在扫描数为 0 也报错。
    """
    bad = []
    scanned = 0
    for f in md:
        base = f.split("/")[-1]
        if not f.startswith("templates/"):
            continue
        if "README" not in base:
            continue
        scanned += 1
        if "不在这里放什么" not in read(f):
            bad.append(f)
    if scanned == 0:
        bad.append("NO container README templates matched (renamed?)")
    rep.add(not bad, "container-readme-sections",
            "scanned=%d bad=%d %s" % (scanned, len(bad), bad[:6] if bad else ""))


# --- 序数一致性 -------------------------------------------------------------
# 2026-10-24 端到端试跑暴露：完成宣告的「第 4 步 / 第 5 步」在不同模板里指反了东西，
# 而当时 17 门全绿。原因是 17 门里**没有任何一门解析序数词**：
# count-claims 只数模板数与 anti-patterns 条数，不校验「第 N 步是哪一步」。
#
# 判据用**性质**而不是名单：只要某行同时出现「完成宣告」与「第 N 步」，
# 它声称的那一步就必须与权威表（completion-ritual.md §一）一致：
#   第 1 步 = 计划内勾选 / 第 2 步 = 逐轮记录 / 第 3 步 = 索引「最近 N 轮」
#   第 4 步 = 代码地图同步 / 第 5 步 = 归档 / 第 6 步 = 修改记录 / 第 7 步 = 收尾快照
# 判据词表只用来判断「这句话在说哪一步」，不要求措辞完全一致。
ORDINAL_STEPS = {
    # 不要用裸「计划」做主题词：文件名 _活跃计划README模板 里就含「计划」，
    # 会把目录树里的纯引用行误判成「第 1 步」的上下文（2026-10-24 实测）。
    1: ("勾选", "验证记录", "偏差记录", "任务分解"),
    2: ("逐轮", "轮次章节", "项目总结"),
    3: ("索引", "最近"),
    4: ("代码地图", "可写范围", "文件作用", "代码结构"),
    5: ("归档",),
    6: ("修改记录",),
    7: ("快照",),
}

# 关键词之后、一个「子句」之内的步号声明。两种写法都要认：
#   第 3 步与第 4 步   -> 两次独立匹配（第二个也带「第」）
#   第 3、4 步         -> 一次匹配，括号里含两个数字
# 旧版用 `[^\n]{0,24}` 做前缀，贪婪地吃掉了第一个步号，于是：
#   「完成宣告第 3 步与第 4 步」只校验了第 4 步；「第 3、5 步」完全不匹配。
# 那是一个**看起来在、其实不在**的门 —— 2026-10-24 复审实测出来的。
ORDINAL_KW_RE = re.compile(r"(?:完成宣告|闭环仪式)")
ORDINAL_CLAIM_RE = re.compile(r"第\s*([\d\s、,，/与和]+?)\s*步")

ORDINAL_SKIP = {
    # 这份是「步数表本身」的定义处，里面的每句话都在给第 N 步下定义，
    # 不需要拿它自己的词表去校验它自己。
    "references/core/completion-ritual.md",
}


def _digits(s):
    return [int(x) for x in re.findall(r"\d+", s)]


def _ordinal_claims(line):
    """返回该行里「关键词 + 步号」的步号列表；无关键词返回 None."""
    m = ORDINAL_KW_RE.search(line)
    if not m:
        return None
    nums = []
    for c in ORDINAL_CLAIM_RE.finditer(line, m.start(), m.start() + 60):
        nums.extend(_digits(c.group(1)))
    return nums or None


def check_ordinal_consistency(md, rep):
    """完成宣告/闭环仪式里出现的「第 N 步」必须与权威步数表一致.

    判据用**性质**：不比对措辞，而是看这句话**同时提到了哪些步**，
    再要求每个步号都能在上下文里找到它自己的主题词。

    窗口 = 本行 + 上文 3 行：
    - 主题词常出现在标题行或列表项，正文与它之间可能隔着 1–3 行说明；
    - **不含下文**是牙齿验证的结论 —— 含下文时，相邻树节点里的「归档计划」
      会被当成第 5 步的主题词，于是写错的「第 5 步」照样通过（假阴性）。

    **覆盖边界（不要高估这道门）**：本行与上文里**一个主题词都没有**的纯引用行，
    门无从判断，会计入 `unjudged` 而不是判红。例如
    「某模板 ← 完成宣告第 3、4 步的落点」这种整行只说步号的写法。
    这类行必须人工核对（`self-check.md` 里有对应的人工项）。
    """
    bad, unjudged = [], 0
    for f in md:
        if f in ORDINAL_SKIP:
            continue
        lines = read(f).split("\n")
        for idx, line in enumerate(lines):
            nums = _ordinal_claims(line)
            if not nums:
                continue
            window = "\n".join(lines[max(0, idx - 3): idx + 1])
            topics = {n for n, ws in ORDINAL_STEPS.items() if any(w in window for w in ws)}
            if not topics:
                unjudged += 1
                continue
            for n in nums:
                if n in ORDINAL_STEPS and n not in topics:
                    bad.append("%s:%d 第%d步(上下文说的是第%s步)" % (
                        f, idx + 1, n, "/".join(map(str, sorted(topics)))))
    rep.add(not bad, "ordinal-consistency",
            "bad=%d unjudged=%d %s" % (len(bad), unjudged, bad[:8] if bad else ""))


def check_template_machine_facts(md, rep):
    """模板的生成块里不得出现本机路径.

    覆盖: 盘符(反斜杠 / 正斜杠) / Unix 家目录 / UNC.
    **避免误伤 URL**: 盘符规则要求盘符字母前面不是字母 —— 否则 https:// 里的 s:/ 会被命中.
    """
    _bs = chr(92)
    pat = re.compile(
        "(?<![A-Za-z])[A-Za-z]:[" + _bs + "/]"
        + "|/home/|/Users/|~/"
        + "|(?:" + _bs + _bs + ")"
    )

    bad = []
    scanned = 0
    for f in md:
        if not f.startswith("templates/"):
            continue
        for lineno, line in in_code_blocks(read(f)):
            scanned += 1
            if pat.search(line):
                bad.append("%s:%d" % (f, lineno))
    if scanned == 0:
        bad.append("NO code-block lines scanned in templates")
    rep.add(not bad, "template-machine-facts",
            "scanned=%d bad=%d %s" % (scanned, len(bad), bad[:4] if bad else ""))


# ---------------------------------------------------------------- 受监督集合
#
# concept count = **由治理设计决定**、不能从文件树推导的数字。
# 它们只能人工登记期望值; 未登记的语义计数**不会**被自动发现 ——
# 这是本门与「无差别普查」的关键区别 (后者在本仓库会产生 500+ 条误报).
# 登记纪律见 references/self-check.md: 新增概念计数 -> 同轮加一行.
CONCEPT_SOURCES = [
    # (正则, 期望值, 说明)   —— 正则第 1 组必须是数字(中文或阿拉伯)
    # **顺序敏感**: 长模式必须排在短模式之前. 例如「保留全部 6 条」要在
    # 「列出的 6 条」这类泛化模式之前被吃掉; 更不能用裸 `\d+ 条` 兜底 ——
    # 那会把「三条纪律」「四条防线」这类合法的**另一个**计数当成漂移 (假阳性).
    (r"保留全部\s*([一二三四五六七八九十0-9]+)\s*条", 6, "six-lessons-retained"),
    (r"([一二三四五六七八九十0-9]+)\s*条提问", 6, "six-questions"),
    (r"([一二三四五六七八九十0-9]+)\s*条核心约束", 4, "four-core-constraints"),
    (r"共性教训（([一二三四五六七八九十0-9]+)条", 6, "six-lessons"),
    # 「五档」只认**带档位语境后缀**的写法（五档阶梯 / 五档速查 / 五档判据 …）。
    # 不能用裸 `N 档` —— 「先低一档」「升一档」是合法叙述, 会天天误报。
    (r"([一二三四五六七八九十0-9]+)档(?:阶梯|速查|判据|长度)", 5, "five-tiers"),
]

# 概念声明**不在此列**的形态（避免把叙述当声明）：
#   - 「第 N 条提问」是序数引用, 不是「共有 N 条」的声明;
#   - 「又追加了三条提问」「变成五条」是在讲**变化**, 不是讲当前总数。
# 这些行整体跳过, 不计入 concept_scanned。
CONCEPT_NARRATIVE_RE = re.compile(
    r"第\s*[一二三四五六七八九十0-9]+\s*条提问"
    r"|(?:又|再|额外|追加|增加到|减少到|变成|改成)\s*[一二三四五六七八九十0-9]+\s*条"
)


def _has_section(body, sec):
    """节必须出现在**标题行**里, 而不是任意正文 —— 否则 §不存在 也会命中正文。

    标题行 = 以 # 1..4 个开头。比对时允许写「§3.7」对应 `### 3.7 ...`。
    """
    for line in body.split("\n"):
        if re.match(r"^#{1,4}\s", line) and sec in line:
            return True
    return False


GATE_TABLE_AUTHORITY = "references/core/gates-and-holds.md"
GATE_TABLE_GENERATED = "templates/_尽调结论模板.md"
# 允许的门禁表结构族。**只认表头字面**, 不认列数 —— 列数相同但列义不同,
# 照样是漂移 (例如把「日志落点」换成「备注」).
GATE_TABLE_SCHEMAS = {
    "full": ["#", "门禁", "命令", "通过判据", "探测不可得时",
             "红了的自愈出口", "日志落点"],
    "summary-3col": ["#", "门禁", "命令"],
}


def _table_header_after(lines, idx):
    """idx 指向表头行, 返回其单元格列表 (已去空白与 **加粗** 标记)."""
    cells = [c.strip() for c in lines[idx].strip().strip("|").split("|")]
    return [c.replace("**", "").strip() for c in cells]



# 「空表」的最小行集: 每张门禁表必须至少有一个数据行和一个不适用哨兵行,
# 否则「删掉模板行」不会改变任何列数, schema 门看不见.
GATE_TABLE_REQUIRED_ROWS = ("| 1 |", "| — |")


def _table_block(lines, header_idx, in_fence):
    """从表头行往下收集整张表 (跳过围栏内的表 —— 那是示例)."""
    if header_idx in in_fence:
        return None
    rows = []
    i = header_idx
    while i < len(lines):
        s = lines[i].strip()
        if not (s.startswith("|") and s.endswith("|")):
            break
        rows.append(s)
        i += 1
    return rows


def check_gate_table_schema(md, rep):
    """门禁表在多个载体里必须同构, 且只有两种被认可的 schema.

    判据 (用性质, 不认文件名):
      1. 每个 `| # | 门禁 |` 表头, 必须**逐字**等于某个已登记 schema;
      2. 同一张表内所有行**列数相等** (表体不能缺列);
      3. 必须含最小行集 (一条数据行 + 一条「不适用」哨兵);
      4. 权威载体与生成件必须是同一个 full schema.
    代码围栏里的表**不算** —— 那是示例, 但模板里的门禁表**在围栏内**
    (模板整体是 ```markdown 代码块), 因此对 templates/ 下的文件不做围栏排除.
    """
    bad = []
    found = 0
    for f in md:
        text = read(f)
        lines = text.split(chr(10))
        # 模板文件整体包在围栏里, 但仍要校验; 其它文件排除围栏内示例.
        in_fence = set() if f.startswith("templates/") else {i for i, _ in in_code_blocks(text)}
        for i, line in enumerate(lines):
            s = line.strip()
            if not (s.startswith("|") and "门禁" in s and "#" in s):
                continue
            cells = _table_header_after(lines, i)
            if len(cells) < 2 or cells[0] != "#" or cells[1] != "门禁":
                continue
            found += 1
            schema_name = None
            for name, want in GATE_TABLE_SCHEMAS.items():
                if cells == want:
                    schema_name = name
                    break
            if schema_name is None:
                bad.append("%s:%d unrecognized gate-table schema %s" % (f, i + 1, cells))
                continue
            rows = _table_block(lines, i, in_fence)
            if rows is None:
                continue
            widths = set(_table_cells(r) for r in rows)
            if len(widths) > 1:
                bad.append("%s:%d gate-table body has mismatched widths %s" % (f, i + 1, sorted(widths)))
            for req in GATE_TABLE_REQUIRED_ROWS:
                if not any(r.startswith(req) for r in rows):
                    bad.append("%s:%d gate table lacks required row %r" % (f, i + 1, req))
            # 权威载体与生成件必须是 full
            if f in (GATE_TABLE_AUTHORITY, GATE_TABLE_GENERATED) and schema_name != "full":
                bad.append("%s:%d must use full schema, got %s" % (f, i + 1, schema_name))
    if found == 0:
        bad.append("NO gate tables found (header changed?)")
    rep.add(not bad, "gate-table-schema",
            "tables=%d bad=%d %s" % (found, len(bad), bad[:6] if bad else ""))


def _validate_fixation_value(val, gate_names):
    """返回 (kind, error). 空载体必须报错 —— 否则 `固化：contract:` 这样的
    「写了等于没写」会通过, 覆盖数被虚高。"""
    val = val.strip()
    if val.startswith("gate:"):
        ref = val[5:].strip()
        if not ref:
            return "gate", "empty gate name"
        if ref not in gate_names:
            return "gate", "unknown gate %r" % ref
        return "gate", None
    if val.startswith("contract:") or val.startswith("discipline:"):
        kind = val.split(":", 1)[0]
        rest = val.split(":", 1)[1]
        path, _, sec = rest.partition("§")
        path = path.strip()
        if not path:
            return kind, "empty carrier path"
        fp = os.path.join(ROOT, path)
        if not os.path.exists(fp):
            return kind, "missing carrier %r" % path
        if not path.endswith(".md") and sec:
            return kind, "section on non-md %r" % path
        if sec and not _has_section(read(path), sec):
            return kind, "section %r not found in %s" % (sec, path)
        return kind, None
    if val.startswith("template:"):
        path = val[9:].strip()
        path, _, sec = path.partition("§")
        path = path.strip()
        if not path:
            return "template", "empty template path"
        if not os.path.exists(os.path.join(ROOT, path)):
            return "template", "missing template %r" % path
        if sec and not _has_section(read(path), sec):
            return "template", "section %r not found in %s" % (sec, path)
        return "template", None
    for kind in ("manual", "none"):
        pref = kind + "("
        if val.startswith(pref) and val.endswith(")"):
            reason = val[len(pref):-1].strip()
            if not reason:
                return kind, "empty %s reason" % kind
            return kind, None
    return None, "malformed 固化 value %r" % val


def check_anti_pattern_fixation(md, rep):
    """每条 anti-pattern 必须声明**带类型的固化载体**, 且载体真实存在.

    设计要点 (2026-10-25 审计后收紧):
      - 固化行必须落在**该条目的头部窗口**里 (标题后 6 行内), 不能是游离在
        附录/正文里的任意一行 —— 否则它会被错误归到上一条, 覆盖数虚高;
      - 代码围栏里的 固化 行不算 (那是示例);
      - 空载体 (`contract:` / `template:` / `manual()`) 报错.

    取值六选一:
        gate:<自检门名> / contract:<路径>§<节> / template:<路径>§<节>
        / discipline:<路径>§<节> / manual(<原因>) / none(<原因>)
    """
    ap = read("references/anti-patterns.md")
    lines = ap.split(chr(10))
    in_fence = {i for i, _ in in_code_blocks(ap)}
    gate_names = set(EXPECTED_GATES)
    bad = []
    declared = {}

    # 按 `### N.` 切块
    blocks = []          # (item_no, start_line, [ (lineno, line) ])
    cur = None
    for i, line in enumerate(lines, 1):
        m = re.match(r"^### (\d+)\. ", line)
        if m:
            cur = [int(m.group(1)), i, []]
            blocks.append(cur)
            continue
        if re.match(r"^## ", line):   # 上级标题结束当前条目
            cur = None
            continue
        if cur is not None:
            cur[2].append((i, line))

    seen = set()
    for no, start, body in blocks:
        if no in seen:
            bad.append("references/anti-patterns.md:%d duplicate item number %d" % (start, no))
        seen.add(no)
        fix_lines = [(i, l) for i, l in body
                     if l.startswith("固化：") and i not in in_fence]
        if not fix_lines:
            bad.append("item %d has no 固化 line" % no)
            continue
        if len(fix_lines) > 1:
            bad.append("item %d has %d 固化 lines (must be 1)" % (no, len(fix_lines)))
        ln, line = fix_lines[0]
        # 必须在头部窗口内 (标题后 6 行), 否则说明它属于别处
        if ln - start > 6:
            bad.append("item %d 固化 line at +%d is outside its header window" % (no, ln - start))
        kind, err = _validate_fixation_value(line[len("固化："):], gate_names)
        if err:
            bad.append("references/anti-patterns.md:%d %s" % (ln, err))
            continue
        declared[kind] = declared.get(kind, 0) + 1

    n_items = len(re.findall(r"^### \d+\.", ap, re.M))
    if n_items == 0:
        bad.append("NO anti-pattern items parsed (heading format changed?)")
    missing = sorted(set(range(1, n_items + 1)) - seen)
    if missing:
        bad.append("items without 固化: %s" % missing)

    # 载体**声明数** != 被门**覆盖**数: 只有 gate: 是机器守住的, 其余是人工/文档承载.
    rep.add(not bad, "anti-pattern-fixation",
            "items=%d declared=%s machine_covered=%d bad=%d %s" % (
                n_items,
                ",".join("%s=%d" % (k, declared[k]) for k in sorted(declared)),
                declared.get("gate", 0),
                len(bad), bad[:5] if bad else ""))



EXPECTED_GATES = [
    "fence-pairing", "template-dead-links", "path-refs-exist", "orphan-files",
    "readme-tree", "md-files", "count-claims", "version-consistency",
    "marker-vocabulary", "stale-phrases", "line-number-refs", "bom-and-eol",
    "gov-root-literal", "tree-tier-markers", "tree-subtree-inherit",
    "tier-table-consistency", "container-readme-sections",
    "ordinal-consistency", "template-machine-facts", "table-shape",
    "anti-pattern-fixation", "gate-table-schema",
]


def main():

    quiet = "--quiet" in sys.argv
    md = walk_md()
    rep = Report()

    try:
        check_fences(md, rep)
    except Exception as exc:
        rep.add(False, "fence-pairing", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_internal_dead_links(md, rep)
    except Exception as exc:
        rep.add(False, "template-dead-links", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_path_refs(md, rep)
    except Exception as exc:
        rep.add(False, "path-refs-exist", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_orphans(md, rep)
    except Exception as exc:
        rep.add(False, "orphan-files", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_tree_vs_files(md, rep)
    except Exception as exc:
        rep.add(False, "readme-tree", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_md_files(md, rep)
    except Exception as exc:
        rep.add(False, "md-files", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_count_claims(md, rep)
    except Exception as exc:
        rep.add(False, "count-claims", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_version_consistency(rep)
    except Exception as exc:
        rep.add(False, "version-consistency", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_markers(md, rep)
    except Exception as exc:
        rep.add(False, "marker-vocabulary", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_stale_phrases(md, rep)
    except Exception as exc:
        rep.add(False, "stale-phrases", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_line_number_refs(md, rep)
    except Exception as exc:
        rep.add(False, "line-number-refs", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_bom_and_eol(rep)
    except Exception as exc:
        rep.add(False, "bom-and-eol", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_gov_root_literal(md, rep)
    except Exception as exc:
        rep.add(False, "gov-root-literal", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_tree_tier_markers(md, rep)
    except Exception as exc:
        rep.add(False, "tree-tier-markers", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_tree_subtree_inherit(md, rep)
    except Exception as exc:
        rep.add(False, "tree-subtree-inherit", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_tier_table_consistency(md, rep)
    except Exception as exc:
        rep.add(False, "tier-table-consistency", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_container_readme_sections(md, rep)
    except Exception as exc:
        rep.add(False, "container-readme-sections", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_ordinal_consistency(md, rep)
    except Exception as exc:
        rep.add(False, "ordinal-consistency", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_template_machine_facts(md, rep)
    except Exception as exc:
        rep.add(False, "template-machine-facts", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_table_shape(md, rep)
    except Exception as exc:
        rep.add(False, "table-shape", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_anti_pattern_fixation(md, rep)
    except Exception as exc:
        rep.add(False, "anti-pattern-fixation", "gate crashed: %s: %s" % (type(exc).__name__, exc))
    try:
        check_gate_table_schema(md, rep)
    except Exception as exc:
        rep.add(False, "gate-table-schema", "gate crashed: %s: %s" % (type(exc).__name__, exc))

    # 按**门名集合**断言，既防静默删门，也防新门漏登记 —— 数行数时删一门
    # 仍等于阈值，整次运行照样 exit 0（#26 防 5）。
    # 旧版只查 `EXPECTED_GATES ⊆ 实际`, 于是「新增门但忘了登记」照样绿;
    # 现在要求两者**集合相等**, 差集任一方向非空都红.
    names = [n for _, n, _ in rep.rows]
    missing = sorted(set(EXPECTED_GATES) - set(names))
    # gate-count 是本函数自己的条件行, 只在有差异时 append, 不参与集合比较.
    unexpected = sorted(set(names) - set(EXPECTED_GATES) - {"gate-count"})
    if missing or unexpected:
        rep.add(False, "gate-count",
                "missing=%s unexpected=%s" % (missing or "none", unexpected or "none"))
    rep.dump(quiet)
    return 0 if rep.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
