import json
from pathlib import Path

# Đường dẫn file dataset
# Lấy root project (thư mục cha của thư mục scripts)
PROJECT_ROOT = Path(__file__).parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "dataset" / "dataset.jsonl"

# Đảm bảo thư mục tồn tại
DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)

# Đọc records hiện có (nếu file tồn tại)
existing_records = []
if DATASET_PATH.exists():
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if content:
            existing_records = [json.loads(line) for line in content.split("\n")]


print(f"📊 Records hiện có: {len(existing_records)}")

# Danh sách records mới sẽ thêm
new_records = []

def add(user_q, assistant_a, category, difficulty="medium", record_id=""):
    new_records.append({
        "messages": [
            {"role": "user", "content": user_q},
            {"role": "assistant", "content": assistant_a}
        ],
        "metadata": {
            "id": record_id,
            "category": category,
            "difficulty": difficulty,
            "source": "OWASP Top 10:2025 Extended"
        }
    })

# ═══════════════════════════════════════════════════════
# IDOR - THÊM CHI TIẾT
# ═══════════════════════════════════════════════════════

add(
    "What is A01:2025 Broken Access Control?",
    "A01:2025 Broken Access Control is the #1 vulnerability in the OWASP Top 10:2025. It refers to failures in enforcing authorization policies, allowing users to act outside their intended permissions. According to OWASP, 100% of applications tested exhibited some form of broken access control. Key statistics: Maximum incidence rate 20.15%, average incidence rate 3.74%, average weighted exploit score 7.04, average weighted impact score 3.84. This category has 40 mapped CWEs, 1,839,701 total occurrences (highest of any category), and 32,654 related CVEs (second highest). Broken Access Control encompasses multiple attack types: IDOR (Insecure Direct Object References), vertical and horizontal privilege escalation, path traversal, force browsing, JWT tampering, CORS misconfiguration, CSRF (Cross-Site Request Forgery), and SSRF (Server-Side Request Forgery). Notable CWEs include CWE-200 (Exposure of Sensitive Information), CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), CWE-352 (CSRF), CWE-918 (SSRF), and CWE-22 (Path Traversal). The key distinction: it is an authorization failure - the system authenticates the user but fails to enforce what they can do. Prevention requires implementing access control server-side, deny-by-default, enforcing record ownership, and testing with multiple user accounts.\n\nSource: OWASP Top 10:2025 (owasp.org/Top10/2025/A01_2025-Broken_Access_Control)",
    "overview", "easy", "A01-OV-101"
)

add(
    "Tell me about OWASP Top 10 2025 A01 Broken Access Control statistics.",
    "According to the OWASP Top 10:2025 official score table, A01:2025 Broken Access Control maintains its #1 position with the following statistics: 100% of tested applications had some form of broken access control. There are 40 CWEs mapped to this category. Maximum incidence rate is 20.15%, average incidence rate is 3.74%, with average coverage of 42.93%. Average weighted exploit score is 7.04, and average weighted impact score is 3.84. Total occurrences in the contributed dataset: 1,839,701 - the highest of any category. Total related CVEs: 32,654 - the second highest number. Notable CWEs include CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-201 (Exposure of Sensitive Information Through Sent Data), CWE-918 (Server-Side Request Forgery), and CWE-352 (Cross-Site Request Forgery). A01 has held the #1 position since OWASP Top 10:2021 (moved up from #5 in 2017). The category covers failures in authorization - the system authenticates users but fails to enforce what they can do. This makes it the most prevalent and impactful web vulnerability globally.\n\nSource: OWASP Top 10:2025 Score Table",
    "overview", "easy", "A01-OV-102"
)

add(
    "What are the main types of Broken Access Control attacks?",
    "OWASP Top 10:2025 identifies 8 main types of Broken Access Control attacks: 1) IDOR (Insecure Direct Object References) - accessing other users' data by manipulating object identifiers in URLs or parameters. 2) Vertical Privilege Escalation - gaining higher-level access (e.g., regular user to admin) through parameter tampering or metadata manipulation. 3) Horizontal Privilege Escalation - accessing data of users at the same privilege level (usually via IDOR). 4) Path Traversal (CWE-22) - accessing files outside the web root using ../ sequences. 5) Force Browsing - guessing URLs to access authenticated or privileged pages. 6) Metadata Manipulation - tampering with JWT tokens, cookies, or hidden fields to escalate privileges. 7) CORS Misconfiguration - allowing unauthorized origins to access APIs with credentials. 8) CSRF (Cross-Site Request Forgery) - tricking authenticated users into performing unintended actions. Additionally, SSRF (Server-Side Request Forgery) is mapped to this category as it involves accessing resources the attacker shouldn't reach. All these attacks share a common root cause: the application fails to properly enforce authorization policies. Prevention requires server-side access control checks on every request, deny-by-default policies, and thorough testing with multiple user accounts.\n\nSource: OWASP Top 10:2025",
    "overview", "medium", "A01-OV-103"
)

add(
    "What is Broken Access Control in simple terms?",
    "Broken Access Control is like having a building with a working front door lock (authentication) but no locks on individual office doors (authorization). Anyone who gets into the building can walk into any office and access any file cabinet.\n\nIn web applications: Authentication is the login process - verifying you are who you claim to be. Authorization is what you can do after logging in - which pages, data, and actions you're allowed to access. Broken Access Control means the authorization part is broken.\n\nSimple example: You log into your bank account (authentication succeeds). You should only see YOUR accounts. But if you change the account number in the URL from /accounts/10023 to /accounts/10024 and the bank shows you someone else's account, that's Broken Access Control. You're authenticated, but the bank didn't check if you OWN account 10024.\n\nWhy it's #1 in OWASP Top 10:2025: It affects 100% of tested applications. Developers focus on authentication (making login secure) but forget authorization (checking permissions on every single request). It's easy to exploit - just change an ID in the URL. And it has huge impact - access to all user data, admin functions, financial systems.\n\nPrevention in one sentence: Check permissions on EVERY request, on the SERVER side, using the authenticated user's identity - never trust the client.\n\nSource: OWASP Top 10:2025",
    "overview", "easy", "A01-OV-104"
)

add(
    "Why is Broken Access Control ranked #1 in OWASP Top 10 2025?",
    "A01:2025 Broken Access Control is ranked #1 in OWASP Top 10:2025 for these specific reasons: 1) Universal prevalence: 100% of tested applications had some form of it, making it unavoidable. 2) Highest occurrence: Over 1.8 million occurrences in the contributed dataset, far exceeding any other category. 3) Design complexity: Access control requires mapping complex business policies, organizational hierarchies, and legal constraints to code - human error is almost inevitable. 4) Severe business impact: Unauthorized data disclosure, financial fraud, regulatory fines (up to 4% of global revenue under GDPR), account takeover. 5) Large attack surface: 40 mapped CWEs covering IDOR, privilege escalation, path traversal, CSRF, SSRF, CORS, metadata manipulation. 6) Difficult to detect: Attacks often look like legitimate authenticated user activity, making automated detection challenging. 7) Often not caught by automated scanners: Requires understanding of business context to test properly. 8) Persistent since 2021: A01 held #1 position since 2021 (moved up from #5 in 2017). These factors combine to make it the most critical and persistent web security challenge. OWASP's recommendation: implement access control server-side, deny-by-default, enforce record ownership, and include functional access control tests in unit and integration testing.\n\nSource: OWASP Top 10:2025",
    "overview", "medium", "A01-OV-105"
)

# ═══════════════════════════════════════════════════════
# SAVE TẤT CẢ VÀO FILE
# ═══════════════════════════════════════════════════════

all_records = existing_records + new_records

# Ghi lại file
with open(DATASET_PATH, 'w', encoding='utf-8') as f:
    for record in all_records:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')

print(f"\n✅ Dataset đã được mở rộng!")
print(f"   Records ban đầu: {len(existing_records)}")
print(f"   Records thêm mới: {len(new_records)}")
print(f"   Tổng cộng: {len(all_records)}")
print(f"\n📁 File đã được lưu tại: {DATASET_PATH}")

# Thống kê categories
categories = {}
for r in all_records:
    cat = r['metadata']['category']
    categories[cat] = categories.get(cat, 0) + 1

print(f"\n📊 Phân bố categories:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"   {cat:25} {count:3d}")