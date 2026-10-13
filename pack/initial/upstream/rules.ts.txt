import {
  decodeBase64Budgeted,
  isStructurallyValidJwt,
  type DecodeBudget,
} from "./encoding.js";
import { mapRange, type MappedView } from "./mapping.js";
import type { FindingEncoding, SecretType } from "./types.js";

export interface InternalFinding {
  readonly ruleId: string;
  readonly secretType: SecretType;
  readonly start: number;
  readonly end: number;
  readonly score: number;
  readonly reasons: readonly string[];
  readonly encoding: FindingEncoding;
}

interface FixedRule {
  readonly ruleId: string;
  readonly secretType: SecretType;
  readonly pattern: RegExp;
  readonly score: number;
  readonly capture?: number;
  readonly validator?: (value: string, budget: DecodeBudget) => boolean;
}

const PUBLIC_EXAMPLES = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  ["sk", "test", "4eC39HqLyjWDarjtT1zdp7dc"].join("_"),
]);

const FIXED_RULES: readonly FixedRule[] = [
  {
    ruleId: "github_fine_grained_pat",
    secretType: "provider_token",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{30,255}\b/g,
    score: 95,
  },
  {
    ruleId: "github_token",
    secretType: "provider_token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    score: 95,
  },
  {
    ruleId: "gitlab_pat",
    secretType: "provider_token",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g,
    score: 95,
  },
  {
    ruleId: "openrouter_key",
    secretType: "provider_token",
    pattern: /\bsk-or-v1-[A-Za-z0-9_-]{32,255}\b/g,
    score: 95,
  },
  {
    ruleId: "anthropic_key",
    secretType: "provider_token",
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,255}\b/g,
    score: 95,
  },
  {
    ruleId: "openai_key",
    secretType: "provider_token",
    pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}\b/g,
    score: 92,
  },
  {
    ruleId: "stripe_secret_key",
    secretType: "provider_token",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,128}\b/g,
    score: 95,
  },
  {
    ruleId: "slack_token",
    secretType: "provider_token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,200}\b/g,
    score: 95,
  },
  {
    ruleId: "slack_webhook",
    secretType: "provider_token",
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{20,300}/g,
    score: 95,
  },
  {
    ruleId: "google_api_key",
    secretType: "api_key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    score: 90,
  },
  {
    ruleId: "google_oauth_token",
    secretType: "access_token",
    pattern: /\bya29\.[0-9A-Za-z_-]{20,255}\b/g,
    score: 95,
  },
  {
    ruleId: "sendgrid_key",
    secretType: "provider_token",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    score: 95,
  },
  {
    ruleId: "npm_token",
    secretType: "provider_token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    score: 95,
  },
  {
    ruleId: "huggingface_token",
    secretType: "provider_token",
    pattern: /\bhf_[A-Za-z0-9]{34,100}\b/g,
    score: 95,
  },
  {
    ruleId: "databricks_pat",
    secretType: "provider_token",
    pattern: /\bdapi[0-9a-fA-F]{32}\b/g,
    score: 95,
  },
  {
    ruleId: "digitalocean_token",
    secretType: "provider_token",
    pattern: /\bdop_v1_[0-9a-fA-F]{64}\b/g,
    score: 95,
  },
  {
    ruleId: "shopify_token",
    secretType: "provider_token",
    pattern: /\bshp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}\b/g,
    score: 95,
  },
  {
    ruleId: "azure_storage_key",
    secretType: "cloud_credential",
    pattern: /\bAccountKey=([A-Za-z0-9+/]{40,120}={0,2})/g,
    capture: 1,
    score: 95,
  },
  {
    ruleId: "aws_access_key_id",
    secretType: "cloud_credential",
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g,
    score: 45,
  },
  {
    ruleId: "jwt",
    secretType: "jwt",
    pattern:
      /\beyJ[A-Za-z0-9_-]{4,2048}\.eyJ[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{8,4096}\b/g,
    score: 60,
    validator: isStructurallyValidJwt,
  },
];

/** Stable detector IDs used by the synthetic coverage gate. */
export const FIXED_RULE_IDS: readonly string[] = Object.freeze(
  FIXED_RULES.map((rule) => rule.ruleId),
);

const PRIVATE_KEY_HEADER =
  /-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g;
const URL_WITH_CREDENTIALS =
  /\b(?:https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):\/\/[^\s"'<>]{1,2048}/gi;
const DATABASE_SCHEME =
  /^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):/i;
const ASSIGNMENT =
  /(?:^|[\s,{;?&])(?:(?:export|set)\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]{0,80})["']?\s*(?::=|[:=])\s*/gim;
const INDEXED_ENV_ASSIGNMENT =
  /(?:^|[\s,(])(?:process\.env|Deno\.env|os\.environ)\s*\[\s*["']([^"']{1,80})["']\s*\]\s*=\s*/gim;
const POWERSHELL_ENV_ASSIGNMENT =
  /(?:^|\s)\$env:([A-Za-z_][A-Za-z0-9_.-]{0,80})\s*=\s*/gim;
const CLI_ARGUMENT_ASSIGNMENT =
  /(?:^|\s)--((?:api[-_]?key)|password|passwd|passphrase|token|client[-_]?secret|secret)(?:=|\s+)/gim;
const FUNCTION_ENV_ASSIGNMENT =
  /\b(?:Deno\.env\.set|process\.env\.set|os\.environ\.set)\(\s*["']([^"']{1,80})["']\s*,\s*/gim;
const NPM_AUTH_TOKEN_ASSIGNMENT =
  /(?:^|[\r\n])\s*(?:(?:\/\/|https?:\/\/)[^\s=]*:)?(_authToken)\s*=\s*/gim;
const COOKIE_HEADER = /(?:^|[\r\n])(?:Cookie|Set-Cookie)\s*:\s*([^\r\n]*)/gim;
const COOKIE_SECRET =
  /(?:^|;\s*)(session(?:id|_id|token)?|auth(?:token)?|access_token|refresh_token|token|jwt|sid)\s*=\s*([^;\s]*)/gim;
const BASIC_AUTH_ARGUMENT =
  /(?:^|\s)(?:-u|--user)(?:=|\s+)(["']?)([^:\s"']{1,256}):([^\s"']{1,1024})\1/gim;
const DOCKER_AUTH_ASSIGNMENT = /(?:^|[\s,{])["']?(auth)["']?\s*:\s*/gim;
const ENTROPY_TOKEN = /[A-Za-z0-9+/_-]{20,512}={0,2}/g;
const YAML_BLOCK_START =
  /(?:(?:!!?[A-Za-z0-9_:.-]+|&[A-Za-z0-9_.-]+)[ \t]+)*(?:[|>](?:(?:[1-9][+-]?)|(?:[+-][1-9]?))?)[ \t]*(?:#[^\r\n]*)?\r?\n/y;
const HEREDOC_START =
  /[^\r\n]{0,2048}?<<-?[ \t]*["']?([A-Za-z_][A-Za-z0-9_]*)["']?[^\r\n]*\r?\n/y;
const PYTHON_STRING_PREFIX = /(?:u8|[rRuUbBfFL]{1,2})("""|'''|"|')/y;
const CSHARP_STRING_PREFIX = /(?:\$@|@\$|@|\$)(")/y;
const RUST_RAW_STRING_PREFIX = /(?:br|rb|r)(#{0,16})"/y;

function encodingPenalty(encoding: FindingEncoding): number {
  return encoding === "percent" ||
    encoding === "json-escaped" ||
    encoding === "base64" ||
    encoding === "whitespace-joined"
    ? 5
    : 0;
}

function encodingReasons(encoding: FindingEncoding): readonly string[] {
  if (encoding === "plain") return ["fixed_format_match"];
  if (encoding === "normalized")
    return ["fixed_format_match", "unicode_normalization"];
  if (encoding === "percent")
    return ["fixed_format_match", "single_level_percent_decode"];
  if (encoding === "json-escaped")
    return ["fixed_format_match", "single_level_json_unicode_decode"];
  if (encoding === "whitespace-joined")
    return ["fixed_format_match", "bounded_line_join"];
  return ["fixed_format_match", "single_level_base64_decode"];
}

export function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  return (
    /^(?:\$\{[A-Z_][A-Z0-9_.]*\}|\$\{\{\s*(?:secrets|vars)\.[A-Z_][A-Z0-9_.-]*\s*\}\}|\$[A-Z_][A-Z0-9_]*|\{\{\s*[A-Z_][A-Z0-9_.-]{0,80}\s*\}\}|<(?:(?:YOUR|INSERT|REPLACE|CHANGE)[_-]?[A-Z0-9_.-]+|REDACTED(?:_[A-Z0-9_.-]+)?|[A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY)[A-Z0-9_.-]*)>|(?:YOUR|INSERT|REPLACE|CHANGE)[_-]?(?:ME|THIS|[A-Z0-9_-]+)|(?:x{4,}|\*{4,}|\.{3,}))$/i.test(
      trimmed,
    ) || /^(?:example|placeholder|redacted)$/i.test(trimmed)
  );
}

export function isExactPublicExample(value: string): boolean {
  return PUBLIC_EXAMPLES.has(value);
}

function safeLiteral(value: string): boolean {
  return isPlaceholder(value) || isExactPublicExample(value);
}

function clonePattern(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags);
}

function capturedRange(
  match: RegExpExecArray,
  capture: number,
): [number, number, string] {
  const whole = match[0];
  const value = match[capture] ?? whole;
  const relative = whole.lastIndexOf(value);
  const start = (match.index ?? 0) + Math.max(0, relative);
  return [start, start + value.length, value];
}

export function scanFixedRules(
  view: MappedView,
  budget: DecodeBudget,
  allowStructuredDecoding: boolean,
): InternalFinding[] {
  const findings: InternalFinding[] = [];

  const privateHeaders = clonePattern(PRIVATE_KEY_HEADER);
  let privateHeader: RegExpExecArray | null;
  while ((privateHeader = privateHeaders.exec(view.text)) !== null) {
    const viewStart = privateHeader.index;
    const keyLabel = privateHeader[1] ?? "PRIVATE KEY";
    const endMarker = `-----END ${keyLabel}-----`;
    const markerStart = view.text.indexOf(endMarker, privateHeaders.lastIndex);
    const complete = markerStart >= 0;
    // The global scanner already caps the input at 1 MiB. If a key header has
    // no matching end marker, redact to EOF so an unchecked private-key tail
    // can never be approved after sanitization.
    const viewEnd = complete
      ? markerStart + endMarker.length
      : view.text.length;
    const [start, end] = mapRange(view, viewStart, viewEnd);
    findings.push({
      ruleId: complete ? "private_key_pem" : "private_key_pem_incomplete",
      secretType: "private_key",
      start,
      end,
      score: (complete ? 100 : 90) - encodingPenalty(view.encoding),
      reasons: [
        ...encodingReasons(view.encoding),
        complete
          ? "complete_private_key_block"
          : "private_key_header_without_bounded_end",
      ],
      encoding: view.encoding,
    });
    privateHeaders.lastIndex = Math.max(privateHeaders.lastIndex, viewEnd);
  }

  for (const rule of FIXED_RULES) {
    if (rule.validator !== undefined && !allowStructuredDecoding) continue;
    const pattern = clonePattern(rule.pattern);
    for (const match of view.text.matchAll(pattern)) {
      const [viewStart, viewEnd, value] = capturedRange(
        match,
        rule.capture ?? 0,
      );
      if (
        safeLiteral(value) ||
        (rule.validator !== undefined && !rule.validator(value, budget))
      )
        continue;
      const [start, end] = mapRange(view, viewStart, viewEnd);
      findings.push({
        ruleId: rule.ruleId,
        secretType: rule.secretType,
        start,
        end,
        score: rule.score - encodingPenalty(view.encoding),
        reasons: encodingReasons(view.encoding),
        encoding: view.encoding,
      });
    }
  }
  return findings;
}

function stripTrailingUrlPunctuation(value: string): string {
  return value.replace(/[),;\]}]+$/g, "");
}

export function scanCredentialUrls(view: MappedView): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const pattern = clonePattern(URL_WITH_CREDENTIALS);
  for (const match of view.text.matchAll(pattern)) {
    const candidate = stripTrailingUrlPunctuation(match[0]);
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      continue;
    }
    // Redis and a few other database clients commonly encode password-only
    // credentials as scheme://:password@host. An empty username must not turn
    // that real credential into a scanner bypass.
    if (parsed.password.length === 0) continue;
    let password = parsed.password;
    try {
      password = decodeURIComponent(password);
    } catch {
      // An invalid escape still represents a non-empty credential.
    }
    if (safeLiteral(password)) continue;

    const viewStart = match.index ?? 0;
    const [start, end] = mapRange(
      view,
      viewStart,
      viewStart + candidate.length,
    );
    const database = DATABASE_SCHEME.test(candidate);
    findings.push({
      ruleId: database ? "database_url_credentials" : "basic_auth_url",
      secretType: database ? "database_credentials" : "password",
      start,
      end,
      score: (database ? 95 : 90) - encodingPenalty(view.encoding),
      reasons: [
        "credential_bearing_url",
        ...(view.encoding === "plain"
          ? []
          : encodingReasons(view.encoding).slice(1)),
      ],
      encoding: view.encoding,
    });
  }
  return findings;
}

function normalizeKey(key: string): string {
  return key
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function typeForSensitiveKey(key: string): SecretType | null {
  const normalized = normalizeKey(key);
  if (
    normalized === "password" ||
    normalized.endsWith("password") ||
    normalized === "passwd" ||
    normalized.endsWith("passwd") ||
    normalized === "passphrase" ||
    normalized.endsWith("passphrase") ||
    normalized === "pwd" ||
    normalized.endsWith("dbpass")
  ) {
    return "password";
  }
  if (normalized.endsWith("privatekey")) return "private_key";
  if (
    normalized.endsWith("awssecretaccesskey") ||
    normalized.endsWith("azurestoragekey")
  ) {
    return "cloud_credential";
  }
  if (normalized.endsWith("apikey")) return "api_key";
  if (
    (normalized.endsWith("token") && normalized !== "jsonwebtoken") ||
    normalized === "authorization"
  )
    return "access_token";
  if (
    normalized.endsWith("clientsecret") ||
    normalized === "secret" ||
    normalized.endsWith("secret") ||
    normalized.endsWith("secretkey") ||
    (!normalized.startsWith("public") && normalized.endsWith("signingkey")) ||
    normalized.endsWith("encryptionkey")
  )
    return "generic_secret";
  if (
    normalized.endsWith("databaseurl") ||
    normalized.endsWith("connectionstring")
  ) {
    return "database_credentials";
  }
  return null;
}

function isConnectionKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return (
    normalized.endsWith("databaseurl") ||
    normalized.endsWith("connectionstring")
  );
}

function connectionContainsCredential(value: string): boolean {
  return (
    /:\/\/[^\s/@]*:[^\s/@]+@/.test(value) ||
    /(?:^|[?;&])(?:password|passwd|pwd|token|sslkey)=([^&;\s]+)/i.test(value) ||
    /(?:^|;)\s*(?:password|passwd|pwd)\s*=\s*[^;\s]+/i.test(value)
  );
}

interface ParsedValue {
  readonly start: number;
  readonly end: number;
  readonly value: string;
  readonly kind: "placeholder" | "regex" | "quoted" | "unquoted" | "multiline";
}

const CODE_LANGUAGE_IDS = new Set([
  "c",
  "cpp",
  "cs",
  "csharp",
  "go",
  "java",
  "javascript",
  "javascriptreact",
  "js",
  "jsx",
  "kotlin",
  "php",
  "py",
  "python",
  "rb",
  "ruby",
  "rs",
  "rust",
  "swift",
  "ts",
  "tsx",
  "typescript",
  "typescriptreact",
]);

function isCodeLikeLanguage(languageId: string | undefined): boolean {
  return (
    languageId !== undefined && CODE_LANGUAGE_IDS.has(languageId.toLowerCase())
  );
}

function isSafeReference(value: string): boolean {
  const trimmed = value.trim();
  if (/^(?:null|undefined|true|false|none|nil)$/i.test(trimmed)) return true;
  if (/^(?:string|number|boolean|unknown|never|any)(?:\[\])?$/.test(trimmed))
    return true;
  if (
    /^(?:string|number|boolean|unknown|never|any|str|String|SecretStr)(?:\[\])?(?:\s*\|\s*(?:null|undefined|None))*!?$/.test(
      trimmed,
    ) ||
    /^Optional\s*\[\s*(?:str|string|String|SecretStr)\s*\]$/.test(trimmed)
  )
    return true;
  if (trimmed.startsWith("/")) {
    const closing = /\/[dgimsuvy]*$/.exec(trimmed);
    const body = closing === null ? "" : trimmed.slice(1, closing.index);
    if (closing !== null && /[\][{}()*+?|^$]/.test(body)) return true;
  }

  const propertyReference =
    /^(?:(?:process\.env|import\.meta\.env|Deno\.env|os\.environ|secrets|vars|var|local|module|config)(?:(?:\??\.[A-Za-z_$][\w$-]*)|(?:\[\s*["'][^"']+["']\s*\]))+)(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/;
  if (propertyReference.test(trimmed)) return true;

  // Code references and fluent validators are not literal credentials. Calls
  // containing string literals are intentionally excluded unless they match a
  // narrow environment getter below.
  if (
    /^[A-Za-z_$][\w$]*(?:(?:\??\.[A-Za-z_$][\w$]*)|(?:\[(?:\d+|["'][^"']+["'])\])|(?:\([^"'`\r\n]*\)))+(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/.test(
      trimmed,
    )
  )
    return true;

  return /^(?:(?:(?:Deno\.env|os\.environ|config|secrets|vault)\.(?:get|require)|os\.getenv|os\.Getenv|System\.getenv|Environment\.GetEnvironmentVariable|std::env::var|std::getenv|getenv|env|getSecret|loadSecret|readSecret|resolveSecret)\(\s*["'][^"']+["']\s*\)\??)(?:\s*(?:\?\?|\|\|)\s*(?:["']{2}|null|undefined))?$/.test(
    trimmed,
  );
}

function isShellCommandSubstitution(value: string): boolean {
  const trimmed = value.trim();
  return (
    /^\$\([^\r\n]{1,512}\)$/.test(trimmed) ||
    /^`[^`\r\n]{1,512}`$/.test(trimmed)
  );
}

function hasExpressionTail(text: string, parsed: ParsedValue): boolean {
  if (parsed.kind !== "quoted" && parsed.kind !== "placeholder") return false;
  let cursor = parsed.end + (parsed.kind === "quoted" ? 1 : 0);
  while (text[cursor] === " " || text[cursor] === "\t") cursor += 1;
  const next = text[cursor];
  return next !== undefined && !/[,;#})\]\r\n]/.test(next);
}

function expressionEnd(text: string, start: number): number {
  let end = start;
  while (
    end < text.length &&
    text[end] !== ";" &&
    !/[\r\n]/.test(text[end] ?? "")
  )
    end += 1;
  while (end > start && /[ \t]/.test(text[end - 1] ?? "")) end -= 1;
  return end;
}

const STRUCTURED_LANGUAGE_IDS = new Set([
  "hcl",
  "json",
  "jsonc",
  "properties",
  "terraform",
  "toml",
  "yaml",
  "yml",
]);

function isDotenvLanguage(languageId: string | undefined): boolean {
  if (languageId === undefined) return false;
  return ["dotenv", "env", "shell-env"].includes(languageId.toLowerCase());
}

function isBareEnvironmentAssignment(
  text: string,
  match: RegExpExecArray,
  assignmentPattern: RegExp,
  languageId: string | undefined,
): boolean {
  if (isDotenvLanguage(languageId)) return true;
  if (assignmentPattern !== ASSIGNMENT) return false;

  const lineStart = text.lastIndexOf("\n", match.index ?? 0) + 1;
  const assignmentEnd = (match.index ?? 0) + match[0].length;
  const assignmentPrefix = text.slice(lineStart, assignmentEnd);
  return /^\s*(?:(?:export|set)\s+)?[A-Z_][A-Z0-9_]*\s*=\s*$/.test(
    assignmentPrefix,
  );
}

function safeContextualValue(
  text: string,
  match: RegExpExecArray,
  assignmentPattern: RegExp,
  parsed: ParsedValue,
  languageId: string | undefined,
): boolean {
  if (safeLiteral(parsed.value) && !hasExpressionTail(text, parsed))
    return true;

  // Quoted and multiline values are literals even if their text happens to
  // look like a type, null, or a code reference. In dotenv-like input, every
  // non-placeholder value is likewise literal. Treating reference-shaped text
  // as executable code there would create a trivial detection bypass.
  const environmentAssignment = isBareEnvironmentAssignment(
    text,
    match,
    assignmentPattern,
    languageId,
  );
  if (environmentAssignment) return false;

  const normalizedLanguage = languageId?.toLowerCase();
  const structuredLanguage =
    normalizedLanguage !== undefined &&
    STRUCTURED_LANGUAGE_IDS.has(normalizedLanguage);
  const lineStart = text.lastIndexOf("\n", match.index ?? 0) + 1;
  const prefix = text.slice(lineStart, (match.index ?? 0) + match[0].length);
  const shellLanguage =
    normalizedLanguage !== undefined &&
    ["bash", "fish", "shell", "shellscript", "sh", "zsh"].includes(
      normalizedLanguage,
    );
  const inferredShellAssignment =
    languageId === undefined && /^\s*[a-z_][A-Za-z0-9_]*\s*=\s*$/.test(prefix);
  if (
    (shellLanguage || inferredShellAssignment) &&
    isShellCommandSubstitution(parsed.value)
  )
    return true;
  if (parsed.kind === "quoted" || parsed.kind === "multiline") return false;
  const inferredStructuredAssignment =
    languageId === undefined &&
    (match[0].includes(":") ||
      /^\s*[a-z_][A-Za-z0-9_.-]*\s*:?=\s*$/.test(prefix));
  const inferredCodeAssignment =
    languageId === undefined &&
    (/\b(?:const|final|let|mut|readonly|return|static|type|interface|enum|var)\b/.test(
      prefix,
    ) ||
      /^\s*(?:[A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)?(?:<[^\r\n=;]{1,128}>)?[*&?]?\s+)+[A-Za-z_$][\w$]*\s*=\s*$/.test(
        prefix,
      ));

  return (
    (isCodeLikeLanguage(languageId) ||
      structuredLanguage ||
      inferredStructuredAssignment ||
      inferredCodeAssignment) &&
    isSafeReference(parsed.value)
  );
}

function isJsonSchemaTypeDescriptor(
  parsed: ParsedValue,
  languageId: string | undefined,
): boolean {
  if (parsed.kind !== "unquoted") return false;
  const normalizedLanguage = languageId?.toLowerCase();
  if (normalizedLanguage !== "json" && normalizedLanguage !== "jsonc")
    return false;
  return /^\{\s*"type"\s*:\s*"(?:array|boolean|integer|null|number|object|string)"(?:\s*[,}]|\s*$)/.test(
    parsed.value,
  );
}

function isClearlyNonLiteralExpression(
  text: string,
  match: RegExpExecArray,
  parsed: ParsedValue,
  languageId?: string,
): boolean {
  if (parsed.kind !== "unquoted") return false;
  const value = parsed.value.trim();
  const lineStart = text.lastIndexOf("\n", match.index ?? 0) + 1;
  const prefix = text.slice(lineStart, match.index ?? 0) + match[0];
  const externalCodeSyntax =
    /\b(?:const|let|var|return|readonly|public|private|protected|type|interface|enum)\b/.test(
      prefix,
    ) || match[0].includes("{");
  if (
    (languageId !== undefined && !isCodeLikeLanguage(languageId)) ||
    (languageId === undefined && !externalCodeSyntax)
  )
    return false;
  if (/^[+-]?(?:\d+(?:\.\d+)?|0x[0-9a-f]+)$/i.test(value)) return false;
  if (
    /^(?:await\s+|new\s+|typeof\s+|this\.|super\.)/.test(value) ||
    /(?:={2,3}|!={1,2}|=>|\?[^:]|\s+as\s+|\s+satisfies\s+|\?\?|\|\||&&)/.test(
      value,
    ) ||
    /^(?:(?:string|number|boolean|unknown|never|any|str|String|SecretStr)(?:\[\])?)(?:\s*\|\s*(?:null|undefined|None))*!?$/.test(
      value,
    ) ||
    /^Optional\s*\[\s*(?:str|string|String|SecretStr)\s*\]$/.test(value) ||
    /^\{\s*["']?type["']?\s*:\s*["'](?:string|number|boolean)["']/.test(
      value,
    ) ||
    (/\b(?:const|let|var|readonly|public|private|protected)\b/.test(prefix) &&
      /^(?:string|number|boolean|unknown|never|any|str|String|SecretStr)(?:\[\])?\s*=/.test(
        value,
      ))
  )
    return true;

  if (/^[A-Za-z_$][\w$]*$/.test(value)) {
    return (
      /(?:password|passwd|token|secret|credential|apiKey|value)$/i.test(
        value,
      ) ||
      /\b(?:const|let|var|return|readonly|public|private|protected)\b/.test(
        prefix,
      )
    );
  }
  return false;
}

function isSymbolicEnumValue(
  text: string,
  match: RegExpExecArray,
  key: string,
  parsed: ParsedValue,
): boolean {
  if (parsed.kind !== "quoted") return false;
  const lineStart = text.lastIndexOf("\n", match.index ?? 0) + 1;
  const prefix = text.slice(lineStart, match.index ?? 0);
  if (!/\benum\b/.test(prefix)) return false;
  const symbolicKey = key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .toLowerCase();
  return parsed.value.toLowerCase() === symbolicKey;
}

function parseAssignmentValue(
  text: string,
  offset: number,
  languageId?: string,
): ParsedValue | null {
  let start = offset;
  while (text[start] === " " || text[start] === "\t") start += 1;
  if (start >= text.length) return null;

  const delimitedPlaceholder = (
    opening: string,
    closing: string,
  ): ParsedValue | null => {
    if (!text.startsWith(opening, start)) return null;
    const close = text.indexOf(closing, start + opening.length);
    if (close < 0) return null;
    const end = close + closing.length;
    return { start, end, value: text.slice(start, end), kind: "placeholder" };
  };
  const placeholder =
    delimitedPlaceholder("${{", "}}") ??
    delimitedPlaceholder("${", "}") ??
    delimitedPlaceholder("{{", "}}") ??
    delimitedPlaceholder("<", ">");
  if (placeholder !== null) return placeholder;

  const prefixedString = clonePattern(PYTHON_STRING_PREFIX);
  prefixedString.lastIndex = start;
  const python = prefixedString.exec(text);
  if (python !== null) {
    const delimiter = python[1] ?? '"';
    const valueStart = prefixedString.lastIndex;
    let close = valueStart;
    let escaped = false;
    while (close < text.length) {
      if (!escaped && text.startsWith(delimiter, close)) break;
      const character = text[close];
      escaped = character === "\\" && !escaped;
      if (character !== "\\") escaped = false;
      close += 1;
    }
    const end = close >= text.length ? text.length : close;
    return {
      start: valueStart,
      end,
      value: text.slice(valueStart, end),
      kind: delimiter.length === 3 ? "multiline" : "quoted",
    };
  }

  const csharpString = clonePattern(CSHARP_STRING_PREFIX);
  csharpString.lastIndex = start;
  if (csharpString.exec(text) !== null) {
    const valueStart = csharpString.lastIndex;
    let close = valueStart;
    while (close < text.length) {
      if (text[close] === '"') {
        if (text[close + 1] === '"') {
          close += 2;
          continue;
        }
        break;
      }
      close += 1;
    }
    return {
      start: valueStart,
      end: close,
      value: text.slice(valueStart, close),
      kind: "quoted",
    };
  }

  const rustString = clonePattern(RUST_RAW_STRING_PREFIX);
  rustString.lastIndex = start;
  const rust = rustString.exec(text);
  if (rust !== null) {
    const valueStart = rustString.lastIndex;
    const closing = `"${rust[1] ?? ""}`;
    const close = text.indexOf(closing, valueStart);
    const end = close < 0 ? text.length : close;
    return {
      start: valueStart,
      end,
      value: text.slice(valueStart, end),
      kind: "quoted",
    };
  }

  const yamlPattern = clonePattern(YAML_BLOCK_START);
  yamlPattern.lastIndex = start;
  const yamlBlock = yamlPattern.exec(text);
  if (yamlBlock !== null) {
    const currentLineStart = text.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
    let keyIndent = 0;
    while (
      text[currentLineStart + keyIndent] === " " ||
      text[currentLineStart + keyIndent] === "\t"
    )
      keyIndent += 1;
    let end = yamlPattern.lastIndex;
    while (end < text.length) {
      const lineEnd = text.indexOf("\n", end);
      const boundedLineEnd = lineEnd < 0 ? text.length : lineEnd + 1;
      const line = text.slice(end, lineEnd < 0 ? text.length : lineEnd);
      if (line.trim().length === 0) {
        end = boundedLineEnd;
        continue;
      }
      let indentation = 0;
      while (line[indentation] === " " || line[indentation] === "\t")
        indentation += 1;
      if (indentation <= keyIndent) break;
      end = boundedLineEnd;
    }
    return { start, end, value: text.slice(start, end), kind: "multiline" };
  }

  const heredocPattern = clonePattern(HEREDOC_START);
  heredocPattern.lastIndex = start;
  const heredoc = heredocPattern.exec(text);
  if (heredoc !== null) {
    const marker = heredoc[1] ?? "";
    const bodyStart = heredocPattern.lastIndex;
    const terminator = new RegExp(
      `(?:^|\\n)[\\t ]*${marker}[\\t ]*(?:\\r?\\n|$)`,
      "g",
    );
    terminator.lastIndex = bodyStart;
    const closing = terminator.exec(text);
    const end = closing === null ? text.length : terminator.lastIndex;
    return { start, end, value: text.slice(start, end), kind: "multiline" };
  }

  const tripleQuote = text.slice(start, start + 3);
  if (tripleQuote === `"""` || tripleQuote === "'''") {
    const valueStart = start + 3;
    const close = text.indexOf(tripleQuote, valueStart);
    const end = close < 0 ? text.length : close;
    return {
      start: valueStart,
      end,
      value: text.slice(valueStart, end),
      kind: "multiline",
    };
  }

  if (
    text[start] === "/" &&
    text[start + 1] !== "/" &&
    text[start + 1] !== "*"
  ) {
    let escaped = false;
    let characterClass = false;
    for (let end = start + 1; end < text.length; end += 1) {
      const character = text[end];
      if (!escaped) {
        if (character === "[") characterClass = true;
        else if (character === "]") characterClass = false;
        else if (character === "/" && !characterClass) {
          let flagsEnd = end + 1;
          while (/[dgimsuvy]/.test(text[flagsEnd] ?? "")) flagsEnd += 1;
          return {
            start,
            end: flagsEnd,
            value: text.slice(start, flagsEnd),
            kind: "regex",
          };
        }
      }
      escaped = character === "\\" && !escaped;
      if (character !== "\\") escaped = false;
      if (character === "\r" || character === "\n") break;
    }
  }

  const quote = text[start];
  if (quote === '"' || quote === "'" || quote === "`") {
    const valueStart = start + 1;
    let escaped = false;
    for (let end = valueStart; end < text.length; end += 1) {
      const character = text[end];
      if (character === quote && !escaped) {
        return {
          start: valueStart,
          end,
          value: text.slice(valueStart, end),
          kind: "quoted",
        };
      }
      escaped = character === "\\" && !escaped;
      if (character !== "\\") escaped = false;
    }
    return {
      start: valueStart,
      end: text.length,
      value: text.slice(valueStart),
      kind: "quoted",
    };
  }

  let valueEnd = start;
  while (valueEnd < text.length && !/[,;#}\r\n]/.test(text[valueEnd] ?? ""))
    valueEnd += 1;
  while (
    valueEnd > start &&
    (text[valueEnd - 1] === " " || text[valueEnd - 1] === "\t")
  )
    valueEnd -= 1;
  if (valueEnd === start) return null;

  // For untyped prompt/text and dotenv input, redact to end-of-line. A comma,
  // semicolon, hash, or brace may be part of an unquoted credential. Structured
  // source selections retain their precise syntax boundary.
  let end = valueEnd;
  if (!isCodeLikeLanguage(languageId) && languageId !== "json") {
    const lineEnd = text.indexOf("\n", valueEnd);
    end = lineEnd < 0 ? text.length : lineEnd;
    while (end > start && text[end - 1] === "\r") end -= 1;
  }
  return {
    start,
    end,
    value: text.slice(start, valueEnd),
    kind: "unquoted",
  };
}

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value)
    counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function entropyThreshold(value: string): number {
  return /^[0-9a-fA-F]+$/.test(value) ? 3 : 4.3;
}

function hasStrongEntropy(value: string): boolean {
  return value.length >= 16 && shannonEntropy(value) >= entropyThreshold(value);
}

function scanAssignmentPattern(
  view: MappedView,
  assignmentPattern: RegExp,
  languageId?: string,
): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const pattern = clonePattern(assignmentPattern);
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(view.text)) !== null) {
    const key = match[1] ?? "";
    const secretType = typeForSensitiveKey(key);
    if (secretType === null) {
      // ASSIGNMENT-style patterns consume both their leading boundary and any
      // whitespace following the separator. Reconsider that trailing
      // whitespace so a harmless label such as `configuration :` cannot hide
      // a sensitive assignment that immediately follows it.
      const trailingWhitespace = /\s+$/.exec(match[0])?.[0].length ?? 0;
      if (trailingWhitespace > 0) {
        pattern.lastIndex = Math.max(
          (match.index ?? 0) + 1,
          pattern.lastIndex - trailingWhitespace,
        );
      }
      continue;
    }
    const valueSyntaxOffset = pattern.lastIndex;
    const parsed = parseAssignmentValue(
      view.text,
      valueSyntaxOffset,
      languageId,
    );
    const hasTail = parsed !== null && hasExpressionTail(view.text, parsed);
    const findingStart = hasTail
      ? (() => {
          let start = valueSyntaxOffset;
          while (view.text[start] === " " || view.text[start] === "\t")
            start += 1;
          return start;
        })()
      : parsed?.start;
    const findingEnd =
      parsed === null
        ? undefined
        : hasTail
          ? expressionEnd(view.text, parsed.end)
          : parsed.end;
    if (findingEnd !== undefined)
      pattern.lastIndex = Math.max(pattern.lastIndex, findingEnd);
    if (parsed === null || parsed.value.length === 0) continue;
    if (
      safeContextualValue(
        view.text,
        match,
        assignmentPattern,
        parsed,
        languageId,
      )
    )
      continue;
    if (isJsonSchemaTypeDescriptor(parsed, languageId)) continue;
    if (isSymbolicEnumValue(view.text, match, key, parsed)) continue;
    if (
      isClearlyNonLiteralExpression(view.text, match, parsed, languageId) &&
      parsed.kind === "unquoted" &&
      !/^[+-]?(?:\d+(?:\.\d+)?|0x[0-9a-f]+)$/i.test(parsed.value.trim())
    )
      continue;
    if (isConnectionKey(key) && !connectionContainsCredential(parsed.value))
      continue;

    const [start, end] = mapRange(
      view,
      findingStart ?? parsed.start,
      findingEnd ?? parsed.end,
    );
    const entropyBonus = hasStrongEntropy(parsed.value) ? 5 : 0;
    findings.push({
      ruleId: `contextual_${secretType}`,
      secretType,
      start,
      end,
      score: 70 + entropyBonus - encodingPenalty(view.encoding),
      reasons: [
        "sensitive_variable_name",
        "structured_assignment",
        ...(entropyBonus > 0 ? ["value_shape_supports_secret"] : []),
        ...(view.encoding === "plain"
          ? []
          : encodingReasons(view.encoding).slice(1)),
      ],
      encoding: view.encoding,
    });
  }
  return findings;
}

function contextualFinding(
  view: MappedView,
  ruleId: string,
  secretType: SecretType,
  viewStart: number,
  viewEnd: number,
  reason: string,
): InternalFinding {
  const [start, end] = mapRange(view, viewStart, viewEnd);
  return {
    ruleId,
    secretType,
    start,
    end,
    score: 70 - encodingPenalty(view.encoding),
    reasons: [
      reason,
      "structured_assignment",
      ...(view.encoding === "plain"
        ? []
        : encodingReasons(view.encoding).slice(1)),
    ],
    encoding: view.encoding,
  };
}

function scanCookieCredentials(view: MappedView): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const headers = clonePattern(COOKIE_HEADER);
  for (const header of view.text.matchAll(headers)) {
    const line = header[1] ?? "";
    const lineStart = (header.index ?? 0) + header[0].lastIndexOf(line);
    const cookies = clonePattern(COOKIE_SECRET);
    for (const cookie of line.matchAll(cookies)) {
      const value = cookie[2] ?? "";
      if (value.length === 0 || safeLiteral(value)) continue;
      const relative = (cookie.index ?? 0) + cookie[0].lastIndexOf(value);
      findings.push(
        contextualFinding(
          view,
          "cookie_session_credential",
          "access_token",
          lineStart + relative,
          lineStart + relative + value.length,
          "credential_cookie_header",
        ),
      );
    }
  }
  return findings;
}

function scanBasicAuthArguments(view: MappedView): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const pattern = clonePattern(BASIC_AUTH_ARGUMENT);
  for (const match of view.text.matchAll(pattern)) {
    const password = match[3] ?? "";
    if (password.length === 0 || safeLiteral(password)) continue;
    const credential = `${match[2] ?? ""}:${password}`;
    const viewStart = (match.index ?? 0) + match[0].lastIndexOf(credential);
    findings.push(
      contextualFinding(
        view,
        "cli_basic_auth",
        "password",
        viewStart,
        viewStart + credential.length,
        "basic_auth_command_argument",
      ),
    );
  }
  return findings;
}

function scanDockerAuth(
  view: MappedView,
  budget: DecodeBudget,
): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const pattern = clonePattern(DOCKER_AUTH_ASSIGNMENT);
  while (pattern.exec(view.text) !== null) {
    const parsed = parseAssignmentValue(view.text, pattern.lastIndex);
    if (parsed !== null)
      pattern.lastIndex = Math.max(pattern.lastIndex, parsed.end);
    if (parsed === null || parsed.value.length === 0) continue;
    const decoded = decodeBase64Budgeted(parsed.value, 4_096, budget);
    if (decoded === null) continue;
    const separator = decoded.indexOf(":");
    if (separator <= 0 || separator === decoded.length - 1) continue;
    if (safeLiteral(decoded.slice(separator + 1))) continue;
    findings.push(
      contextualFinding(
        view,
        "docker_auth",
        "password",
        parsed.start,
        parsed.end,
        "docker_auth_base64_credentials",
      ),
    );
  }
  return findings;
}

export function scanContextualAssignments(
  view: MappedView,
  budget: DecodeBudget,
  languageId?: string,
  allowStructuredDecoding = true,
): InternalFinding[] {
  return [
    ...scanAssignmentPattern(view, ASSIGNMENT, languageId),
    ...scanAssignmentPattern(view, INDEXED_ENV_ASSIGNMENT, languageId),
    ...scanAssignmentPattern(view, POWERSHELL_ENV_ASSIGNMENT, languageId),
    ...scanAssignmentPattern(view, CLI_ARGUMENT_ASSIGNMENT, languageId),
    ...scanAssignmentPattern(view, FUNCTION_ENV_ASSIGNMENT, languageId),
    ...scanAssignmentPattern(view, NPM_AUTH_TOKEN_ASSIGNMENT, languageId),
    ...scanCookieCredentials(view),
    ...scanBasicAuthArguments(view),
    ...(allowStructuredDecoding ? scanDockerAuth(view, budget) : []),
  ];
}

function entropyExcluded(value: string): boolean {
  return (
    value ===
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ||
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(
      value,
    ) ||
    (/^[0-9a-fA-F]+$/.test(value) &&
      [32, 40, 64, 96, 128].includes(value.length)) ||
    /^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/i.test(value) ||
    /^[0-9A-HJKMNP-TV-Z]{26}$/.test(value) ||
    /^(?:pk_(?:live|test)_|acct_|cus_|price_|prod_|pi_)[A-Za-z0-9_-]+$/.test(
      value,
    ) ||
    // Identifiant d'appel d'outil Anthropic, repris tel quel dans les
    // notifications de tâche que Claude Code soumet comme prompt.
    /^(?:srv)?toolu_[A-Za-z0-9]{24}$/.test(value) ||
    /^REDACTED_[A-Za-z0-9_]+$/.test(value) ||
    /^(?:\/|node_modules\/)[A-Za-z0-9._/-]+$/.test(value) ||
    safeLiteral(value)
  );
}

function isShellEnvironmentPath(
  text: string,
  start: number,
  value: string,
): boolean {
  const prefix = text.slice(Math.max(0, start - 5), start);
  const hasEnvironmentSigil =
    text[start - 1] === "$" || prefix.toLowerCase() === "$env:";
  return (
    hasEnvironmentSigil &&
    /^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z0-9._/-]+$/.test(value)
  );
}

export function scanEntropy(view: MappedView): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const pattern = clonePattern(ENTROPY_TOKEN);
  for (const match of view.text.matchAll(pattern)) {
    const value = match[0];
    const viewStart = match.index ?? 0;
    if (
      entropyExcluded(value) ||
      isShellEnvironmentPath(view.text, viewStart, value) ||
      !hasStrongEntropy(value)
    )
      continue;
    const [start, end] = mapRange(view, viewStart, viewStart + value.length);
    findings.push({
      ruleId: "high_entropy",
      secretType: "high_entropy",
      start,
      end,
      score:
        35 -
        (view.encoding === "normalized" ? 0 : encodingPenalty(view.encoding)),
      reasons: [
        "high_entropy_shape",
        "unanchored_entropy_is_warning_only",
        ...(view.encoding === "normalized" ? ["unicode_normalization"] : []),
      ],
      encoding: view.encoding,
    });
  }
  return findings;
}
