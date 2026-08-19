#!/usr/bin/env python3
"""
🔐 PassCheck — 密码强度检查器
纯 Python 标准库，零依赖
"""

import sys
import re
import math
import getpass
import argparse

# 常见弱密码 Top 200 (简化版)
COMMON_PASSWORDS = {
    "123456","password","123456789","guest","qwerty","12345678","111111",
    "12345","col123456","123123","1234567890","password1","admin","abc123",
    "1q2w3e4r","letmein","welcome","monkey","dragon","password123",
    "iloveyou","sunshine","princess","1234","qwerty123","000000",
    "superman","master","football","baseball","trustno1","hello",
    "freedom","whatever","qazwsx","shadow","michael","jordan",
    "harley","robert","matthew","jordan","asshole","daniel",
    "andrew","soccer"," summers","qwerty1","winner","test",
    "pass123","passw0rd","admin123","root","toor","pass",
    "changeme","default","secret","login","user","guest",
    "Password1","P@ssw0rd","P@ssword1","Passw0rd!","Welcome1",
    "Changeme1","Summer2024","Winter2024","Spring2024","Autumn2024",
    "Qwerty123","Abc12345","Admin123","Root123",
}

# 键盘连续序列
KEYBOARD_SEQUENCES = [
    "qwertyuiop","asdfghjkl","zxcvbnm",
    "1234567890","0987654321",
    "qazwsxedc","pqowieuryt",
    "!@#$%^&*()",
]

# 日期模式
DATE_PATTERNS = [
    re.compile(r"(19|20)\d{2}"),        # 1900-2099
    re.compile(r"\d{2}[/\-.\d]\d{2}[/\-.\d]\d{2,4}"),  # 01/01/2020
    re.compile(r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)", re.IGNORECASE),
]


def shannonEntropy(password):
    if not password:
        return 0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(password)
        entropy -= p * math.log2(p)
    return entropy * len(password)


def charsetSize(password):
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"\d", password):   size += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~ ]", password): size += 33
    if not password: return 1
    # 检查是否有其他字符
    if re.search(r"[^a-zA-Z\d!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~ ]", password):
        size += 32
    return max(size, 1)


def crackTimeEstimate(password):
    entropy = shannonEntropy(password)
    charset = charsetSize(password)
    if charset == 0:
        return 0, "instant"
    # 假设 10^10 次猜测/秒 (高性能硬件)
    guesses_per_second = 1e10
    total_guesses = (charset ** len(password)) / 2  # 平均猜测一半就能破解
    seconds = total_guesses / guesses_per_second
    return seconds, formatTime(seconds)


def formatTime(seconds):
    if seconds < 1:
        return "instant"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 86400*30:
        return f"{seconds/86400:.1f} days"
    if seconds < 86400*365:
        return f"{seconds/86400/30:.1f} months"
    years = seconds / 86400 / 365
    if years < 1000:
        return f"{years:.1f} years"
    if years < 1e6:
        return f"{years/1000:.0f}K years"
    if years < 1e9:
        return f"{years/1e6:.0f}M years"
    return "centuries (effectively uncrackable)"


def checkPassword(password):
    checks = []
    score = 0
    issues = []
    good = []
    
    # 1. 长度
    length = len(password)
    if length >= 20:
        score += 25
        good.append("长度 ≥20，非常充足")
    elif length >= 16:
        score += 20
        good.append("长度 ≥16，很安全")
    elif length >= 12:
        score += 15
        good.append("长度 ≥12，达标")
    elif length >= 8:
        score += 8
        good.append("长度 ≥8，基本达标")
    else:
        score += 2
        issues.append(f"长度仅 {length}，建议至少 8 位")
    
    # 2. 字符种类
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~ ]", password))
    
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    if has_lower:
        score += 5
        good.append("包含小写字母")
    else:
        issues.append("缺少小写字母")
    if has_upper:
        score += 5
        good.append("包含大写字母")
    else:
        issues.append("缺少大写字母")
    if has_digit:
        score += 5
        good.append("包含数字")
    else:
        issues.append("缺少数字")
    if has_special:
        score += 10
        good.append("包含特殊字符")
    else:
        issues.append("缺少特殊字符")
    
    # 3. 常见弱密码检测
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        score -= 30
        issues.append("🚨 这是常见弱密码！已是公开的破解字典中的条目")
    else:
        # 部分匹配
        for cp in COMMON_PASSWORDS:
            if cp in lower and len(cp) >= 4:
                issues.append(f"包含常见弱密码片段: '{cp}'")
                score -= 5
                break
    
    # 4. 键盘连续序列
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i+3]
            if chunk in lower:
                issues.append(f"包含键盘连续序列: '{chunk}'")
                score -= 5
                break
        else:
            continue
        break
    
    # 5. 日期模式
    for pattern in DATE_PATTERNS:
        if pattern.search(password):
            issues.append("包含日期模式，容易被社工猜测")
            score -= 5
            break
    
    # 6. 重复字符
    if re.search(r"(.)\1{2,}", password):
        issues.append("包含连续重复字符 (如 aaa, 111)")
        score -= 5
    
    # 7. 常见名字/单词替换
    leet_map = str.maketrans("013458@$", "oieastbas")
    deleet = lower.translate(leet_map)
    common_words = ["password","admin","welcome","letmein","master","superman",
                     "dragon","monkey","shadow","qwerty","login","hello"]
    for word in common_words:
        if word in deleet:
            issues.append(f"包含常见弱密码词汇: '{word}'")
            score -= 5
            break
    
    # 8. 信息熵加分
    entropy = shannonEntropy(password)
    if entropy > 35:
        score += 10
        good.append(f"信息熵高 ({entropy:.1f} bits)")
    elif entropy > 20:
        score += 5
    else:
        issues.append(f"信息熵低 ({entropy:.1f} bits)，字符多样性不足")
    
    # 9. 重复模式
    if len(password) >= 4:
        pattern_len = len(password) // 2
        if pattern_len >= 2:
            first_half = password[:pattern_len]
            second_half = password[pattern_len:]
            if first_half == second_half:
                issues.append("密码体由重复模式构成")
                score -= 10
    
    # Clamp score
    score = max(0, min(100, score))
    
    # 评级
    if score >= 81:
        level = "🛡️ 极强"
    elif score >= 61:
        level = "🟢 强"
    elif score >= 41:
        level = "🟡 中等"
    elif score >= 21:
        level = "🔴 弱"
    else:
        level = "💀 极弱"
    
    # 破解时间
    crack_seconds, crack_text = crackTimeEstimate(password)
    
    return {
        "score": score,
        "level": level,
        "issues": issues,
        "good": good,
        "entropy": entropy,
        "crack_time": crack_text,
        "length": length,
        "char_types": char_types,
    }


def printReport(password, result):
    sep = "═" * 49
    print(f"\n{sep}")
    print("  🔐 PassCheck — 密码强度报告")
    print(sep)
    print(f"\n  密码长度: {result['length']} 位")
    print(f"  字符种类: {result['char_types']}/4")
    print(f"  信息熵: {result['entropy']:.1f} bits")
    print(f"  估算破解时间: {result['crack_time']}")
    print()
    print(f"  ⭐ 强度评分: {result['score']}/100")
    print(f"  等级: {result['level']}")
    print()
    
    if result["good"]:
        print("  ✅ 好的方面:")
        for g in result["good"]:
            print(f"    ✓ {g}")
    
    if result["issues"]:
        print("\n  ⚠️ 发现问题:")
        for i in result["issues"]:
            print(f"    ✗ {i}")
    
    if result["score"] < 61:
        print("\n  💡 改进建议:")
        print("    - 增加密码长度到 12 位以上")
        print("    - 混合大小写字母、数字、特殊字符")
        print("    - 避免使用常见单词和日期")
        print("    - 使用密码管理器生成随机密码")
    
    print(f"\n{sep}\n")


def main():
    parser = argparse.ArgumentParser(description="🔐 PassCheck — 密码强度检查器")
    parser.add_argument("password", nargs="?", default=None, help="要检查的密码")
    parser.add_argument("--file", type=str, help="批量检查文件中的密码")
    parser.add_argument("--score-only", action="store_true", help="只输出评分")
    args = parser.parse_args()
    
    if args.file:
        try:
            with open(args.file, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"❌ 无法读取文件: {e}")
            sys.exit(1)
        for pwd in passwords:
            result = checkPassword(pwd)
            if args.score_only:
                print(f"{pwd}\t{result['score']}/100\t{result['level']}")
            else:
                printReport(pwd, result)
        return
    
    if args.password:
        password = args.password
    else:
        print("🔐 请输入密码进行检查:")
        password = getpass.getpass("> ")
    
    if not password:
        print("❌ 密码不能为空")
        sys.exit(1)
    
    result = checkPassword(password)
    if args.score_only:
        print(f"{result['score']}/100\t{result['level']}")
    else:
        printReport(password, result)


if __name__ == "__main__":
    main()
