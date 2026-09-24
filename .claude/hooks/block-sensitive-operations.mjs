// PreToolUse: 危険語を含むコマンドや、認証情報のパスへのアクセスを実行前に拒否する
// 入力が読めないなどで判定できないときも拒否に倒す。exit 1 で落ちると
// Claude Code は非ブロッキングのエラーとして扱い、ツールをそのまま実行してしまう。

const COMMAND_BLOCK = [
  // 外部送信
  /\bcurl\b/i,
  /\bwget\b/i,
  /Invoke-(WebRequest|RestMethod)/i,
  /\b(iwr|irm)\b/i,
  /Start-BitsTransfer/i,
  /Net\.WebClient/i,
  // 中身が見えない実行(-EncodedCommand は -e / -ec / -enc などの省略形も通る)
  /\b(powershell|pwsh)(\.exe)?\b[^|;&]*\s[-\/]e(c|n\w*)?\b/i,
  /FromBase64String/i,
  // スクリーンショット・画面キャプチャ
  /screen\s*shot/i,
  /screen\s*capture/i,
  /CopyFromScreen/i,
  /PrintScreen|\{PRTSC\}/i,
  /\bBitBlt\b/i,
  /\bPrintWindow\b/i,
  /GraphicsCapture/i,
  /\bImageGrab\b/i,
  // クリップボード
  /clipboard/i,
  /\bpyperclip\b/i,
  // Windows の資格情報
  /\bcmdkey\b/i,
  /\bvaultcmd\b/i,
  /Get-StoredCredential/i,
  /PasswordVault/i,
  /ProtectedData|CryptUnprotectData/i,
  // ここに止めたい語を足していく
];

// コマンド文字列とファイル系ツールのパスの両方に当てる
const SECRET_PATHS = [
  /(^|[\s'"~=\\/])\.ssh\b/i,
  /\bid_(rsa|dsa|ecdsa|ed25519)\b/i,
  /(^|[\s'"~=\\/])\.(aws|azure|kube)[\\/]/i,
  /\.git-credentials|(^|[\s'"~=\\/])_?\.?netrc\b/i,
  /\.docker[\\/]config\.json/i,
  /(gh|GitHub CLI)[\\/]hosts\.ya?ml/i,
  /(Chrome|Edge|Brave-Browser)[\\/]User Data/i,
  /Mozilla[\\/]Firefox[\\/]Profiles/i,
  /\b(Login Data|cookies\.sqlite|logins\.json|key4\.db)\b/i,
  /Microsoft[\\/](Credentials|Vault|Protect)\b/i,
];

const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
const PATH_FIELDS = ["file_path", "path", "pattern", "glob", "notebook_path"];

function deny(reason) {
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

function check(input) {
  const ti = input.tool_input ?? {};
  if (SHELL_TOOLS.has(input.tool_name)) {
    const cmd = String(ti.command ?? "");
    const hit = [...COMMAND_BLOCK, ...SECRET_PATHS].find((re) => re.test(cmd));
    if (hit) deny(`blocked by policy: ${hit}`);
    return;
  }
  for (const field of PATH_FIELDS) {
    const value = ti[field];
    if (typeof value !== "string") continue;
    const hit = SECRET_PATHS.find((re) => re.test(value));
    if (hit) deny(`blocked by policy (${field}): ${hit}`);
  }
}

try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  check(JSON.parse(raw));
} catch (err) {
  // exit 2 はブロッキングエラー。stderr が Claude に理由として渡る
  console.error(`hook failed, denying by default: ${err?.message ?? err}`);
  process.exit(2);
}
