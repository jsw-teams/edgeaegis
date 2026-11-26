// @ts-nocheck
/**
 * EdgeAegis's first-party SecLang state machine (no ModSecurity process).
 * Compiles native rules, source includes and data into executable transaction instructions.
 * Data is a Request-like object or real Web Request; no I/O occurs while executing.
 */

import ipaddr from "ipaddr.js";
import { bodyProcessor, parseBody, xmlValues } from "./body.js";
import { asciiLower, formEntries, fromOctets, octets, utf8Bytes } from "./bytes.js";
import type { InjectionDetectors } from "./libinjection.js";
import type { SecLangRegex, SecLangRegexBackend } from "./pcre2.js";
import { createPhraseMatcher } from "./pm.js";
import { expandSecLangSources, type SecLangSourceOptions, sourcePath } from "./sources.js";
import { CollectionStore, collectionRecord } from "./state.js";
import { transform, transformations } from "./transforms.js";
import { defaultUnicodeMap, parseUnicodeMap } from "./unicode.js";

const utf8Encoder = new TextEncoder();
const utf8FatalDecoder = new TextDecoder("utf-8", { fatal: true });

function parseIdRange(range: string): [number, number] {
  const dash = range.indexOf("-");
  if (dash < 0) {
    const n = Number(range);
    return [n, n];
  }
  return [Number(range.slice(0, dash)), Number(range.slice(dash + 1))];
}

export { createInjectionDetectors } from "./libinjection.js";
export type { SecLangRegexBackend } from "./pcre2.js";
export { createPCRE2Backend, PCRE2Error } from "./pcre2.js";
export { compactSecLangFiles } from "./sources.js";

export function splitActions(source) {
  const entries = [];
  let current = "";
  let quote = false;
  let escaped = false;
  for (const ch of source) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === "'") quote = !quote;
    if (ch === "," && !quote) {
      entries.push(current.trim());
      current = "";
    } else current += ch;
  }
  if (quote) throw new Error("Unterminated SecLang action quote");
  if (current.trim()) entries.push(current.trim());
  return entries;
}

function parseActions(text) {
  const out = [];
  for (const part of splitActions(text)) {
    const colon = part.indexOf(":");
    const name = (colon < 0 ? part : part.slice(0, colon)).toLowerCase();
    let arg = colon < 0 ? undefined : part.slice(colon + 1);
    if (arg?.startsWith("'") && arg.endsWith("'")) arg = arg.slice(1, -1);
    out.push({ name, arg });
  }
  return out;
}

const ACTIONS = new Set([
  "id",
  "phase",
  "deny",
  "block",
  "pass",
  "log",
  "nolog",
  "auditlog",
  "noauditlog",
  "t",
  "msg",
  "logdata",
  "tag",
  "ver",
  "severity",
  "rev",
  "maturity",
  "accuracy",
  "chain",
  "setvar",
  "skipafter",
  "status",
  "capture",
  "ctl",
  "multimatch",
  "initcol",
  "expirevar",
  "deprecatevar",
  "skip",
]);
const OPERATOR_NAMES = new Set([
  "streq",
  "contains",
  "beginswith",
  "endswith",
  "within",
  "eq",
  "lt",
  "le",
  "ge",
  "gt",
  "rx",
  "pm",
  "pmfromfile",
  "detectsqli",
  "detectxss",
  "ipmatch",
  "ipmatchfromfile",
  "unconditionalmatch",
  "validatebyterange",
  "validateurlencoding",
  "validateutf8encoding",
]);
const TRANSFORM_NAMES = new Set(Object.keys(transformations));
const BYTE_COLLECTIONS = new Set([
  "ARGS",
  "ARGS_NAMES",
  "ARGS_GET",
  "ARGS_POST",
  "ARGS_GET_NAMES",
  "ARGS_POST_NAMES",
  "TX",
  "IP",
  "GLOBAL",
  "MATCHED_VAR",
  "MATCHED_VAR_NAME",
  "MATCHED_VARS",
  "REQUEST_HEADERS",
  "REQUEST_HEADERS_NAMES",
  "REQUEST_COOKIES",
  "REQUEST_COOKIES_NAMES",
  "FILES",
  "FILES_NAMES",
  "MULTIPART_PART_HEADERS",
  "RESPONSE_BODY",
  "REQUEST_BODY",
  "REQUEST_FILENAME",
  "REQUEST_BASENAME",
]);
const VARIABLES = new Set([
  "REQUEST_METHOD",
  "REQUEST_URI",
  "REQUEST_URI_RAW",
  "REQUEST_FILENAME",
  "REQUEST_BASENAME",
  "REQUEST_HEADERS",
  "REQUEST_HEADERS_NAMES",
  "REQUEST_COOKIES",
  "REQUEST_COOKIES_NAMES",
  "REQUEST_BODY",
  "ARGS",
  "ARGS_NAMES",
  "ARGS_GET",
  "ARGS_GET_NAMES",
  "ARGS_POST",
  "ARGS_POST_NAMES",
  "ARGS_COMBINED_SIZE",
  "REQUEST_BODY_LENGTH",
  "MATCHED_VAR",
  "MATCHED_VAR_NAME",
  "QUERY_STRING",
  "TX",
  "REQUEST_PROTOCOL",
  "REQUEST_LINE",
  "REMOTE_ADDR",
  "UNIQUE_ID",
  "REQBODY_PROCESSOR",
  "REQBODY_ERROR",
  "REQBODY_ERROR_MSG",
  "REQBODY_PROCESSOR_ERROR",
  "REQBODY_PROCESSOR_ERROR_MSG",
  "INBOUND_DATA_ERROR",
  "MULTIPART_STRICT_ERROR",
  "FILES",
  "FILES_NAMES",
  "FILES_COMBINED_SIZE",
  "MULTIPART_PART_HEADERS",
  "XML",
  "RESPONSE_BODY",
  "RESPONSE_HEADERS",
  "RESPONSE_STATUS",
  "MATCHED_VARS",
  "IP",
  "GLOBAL",
]);

function compilerError(message, statement) {
  return {
    line: statement.line,
    file: statement.file,
    reason: message,
    rule: statement.args?.[2]?.match(/id:(\d+)/)?.[1],
  };
}

function compileSelector(text, regexBackend) {
  const selectors = [];
  const parts = [];
  let begin = 0;
  let regex = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "/" && (regex || (text[i - 1] === ":" && !/^!?&?XML:/i.test(text.slice(begin, i)))))
      regex = !regex;
    if (ch === "|" && !regex) {
      parts.push(text.slice(begin, i));
      begin = i + 1;
    }
  }
  if (regex) throw new Error("Unterminated selector regex");
  parts.push(text.slice(begin));
  for (const entry of parts) {
    const negative = entry.startsWith("!");
    const part = negative ? entry.slice(1) : entry;
    const count = part.startsWith("&");
    const field = count ? part.slice(1) : part;
    const colon = field.indexOf(":");
    const key = colon < 0 ? undefined : field.slice(colon + 1);
    const name = (colon < 0 ? field : field.slice(0, colon)).toUpperCase();
    if (!VARIABLES.has(name)) throw new Error(`Unsupported variable collection: ${name}`);
    if (key?.includes("%{")) throw new Error("Dynamic selector macros are not supported");
    let keyRegex: SecLangRegex | undefined;
    if (name !== "XML" && key?.startsWith("/") && key.endsWith("/")) {
      if (!regexBackend) throw new Error("Regex selectors require the PCRE2 backend");
      keyRegex = regexBackend.compile(`(?i)${key.slice(1, -1)}`);
    }
    selectors.push({
      negative,
      count,
      name,
      key,
      keyRegex,
      foldedKey: key === undefined ? undefined : asciiLower(utf8Bytes(key)),
    });
  }
  if (!selectors.length || selectors.every((x) => x.negative))
    throw new Error("No positive variable selector");
  return selectors;
}
function compileOperator(text, phraseFiles, regexBackend, detectors, fileName) {
  const negated = text.startsWith("!");
  const raw = negated ? text.slice(1) : text;
  const m = /^@([A-Za-z][A-Za-z0-9]*)(?:\s+([\s\S]*))?$/.exec(raw);
  if (!m && raw.startsWith("@")) throw new Error("Malformed operator");
  const op = m ? m[1].toLowerCase() : "rx";
  const operand = m ? (m[2] ?? "") : raw;
  if (!OPERATOR_NAMES.has(op)) throw new Error(`Unsupported operator ${op}`);
  const dynamic = operand.includes("%{");
  if (dynamic) {
    if (["pm", "pmfromfile", "ipmatch", "ipmatchfromfile", "validatebyterange"].includes(op))
      throw new Error("Unsupported operator macro");
    validateMacros(operand);
  }
  let regex: SecLangRegex | undefined;
  if (op === "rx" && !regexBackend) throw new Error("Regex operators require the PCRE2 backend");
  if (op === "rx" && !dynamic) {
    try {
      regex = regexBackend.compile(operand);
    } catch (error) {
      throw new Error(`Regex compile failed: ${String(error.message)}`);
    }
  }
  let phrases: string[] | undefined;
  if (["pmfromfile", "ipmatchfromfile"].includes(op)) {
    phrases = [];
    for (const file of operand.split(/\s+/).filter(Boolean)) {
      const path = sourcePath(fileName ?? "main.conf", file);
      const entries = phraseFiles?.[path] ?? phraseFiles?.[file];
      if (!Array.isArray(entries) || !entries.every((v) => typeof v === "string"))
        throw new Error(`Missing explicit operator data file: ${file}`);
      phrases.push(...entries);
    }
  } else if (op === "pm") phrases = operand.split(/\s+/).filter(Boolean);
  if (["detectsqli", "detectxss"].includes(op) && !detectors)
    throw new Error(`Operator ${op} requires the libinjection primitive backend`);
  let ranges = [];
  if (op === "validatebyterange") {
    ranges = operand.split(",").map((part) => {
      const range = /^(\d+)(?:-(\d+))?$/.exec(part.trim());
      if (!range) throw new Error("Invalid byte range");
      const start = Number(range[1]),
        end = Number(range[2] ?? range[1]);
      if (start > end || end > 255) throw new Error("Invalid byte range");
      return [start, end];
    });
  }
  let networks = [];
  if (["ipmatch", "ipmatchfromfile"].includes(op))
    networks = (op === "ipmatchfromfile" ? phrases.join("\n") : operand)
      .split(/[\s,]+/)
      .filter(Boolean)
      .map((value) =>
        value.includes("/")
          ? ipaddr.parseCIDR(value)
          : [ipaddr.parse(value), ipaddr.parse(value).kind() === "ipv4" ? 32 : 128],
      );
  const loweredPhrases = phrases?.map((phrase) => asciiLower(utf8Bytes(phrase)));
  const phraseMatcher =
    op === "pm" || op === "pmfromfile" ? createPhraseMatcher(loweredPhrases ?? []) : undefined;
  return {
    op,
    operand: utf8Bytes(operand),
    negated,
    regex,
    phrases: loweredPhrases,
    phraseMatcher,
    dynamic,
    detectors,
    ranges,
    networks,
    dynamicRegexBackend: regexBackend?.untracked ?? regexBackend,
  };
}
function compileActionSet(actions) {
  const data = {
    phase: undefined,
    transformations: [],
    changes: [],
    controls: [],
    initializers: [],
    effects: [],
    tags: [],
    log: true,
    audit: true,
  };
  for (const { name, arg } of actions) {
    if (!ACTIONS.has(name)) throw new Error(`Unsupported action ${name}`);
    if (name === "phase") {
      const phase = Number(arg);
      if (![1, 2, 3, 4, 5].includes(phase)) throw new Error("Unsupported SecLang phase");
      data.phase = phase;
    } else if (name === "id") {
      if (!/^\d{1,10}$/.test(arg ?? "")) throw new Error("Invalid rule id");
      data.id = arg;
    } else if (name === "chain") data.chain = true;
    else if (["deny", "block", "pass"].includes(name)) data.decision = name;
    else if (name === "t") {
      const v = arg?.toLowerCase();
      if (!TRANSFORM_NAMES.has(v)) throw new Error(`Unsupported transform ${arg}`);
      if (v === "none") data.transformations = [];
      else data.transformations.push(v);
    } else if (name === "setvar") {
      const m = /^(!)?(tx|ip|global)\.([^=]+)(?:=([\s\S]*))?$/i.exec(arg ?? "");
      if (!m) throw new Error("Unsupported setvar expression");
      validateMacros(m[3]);
      validateMacros(m[4] ?? "");
      const change = {
        collection: m[2].toUpperCase(),
        name: utf8Bytes(m[3]),
        value: utf8Bytes(m[4] ?? "1"),
        remove: Boolean(m[1]),
      };
      data.changes.push(change);
      data.effects.push({ type: "setvar", ...change });
    } else if (name === "expirevar" || name === "deprecatevar") {
      const match = /^(tx|ip|global)\.([^=]+)=([\s\S]+)$/i.exec(arg ?? "");
      if (!match) throw new Error(`Invalid ${name} expression`);
      validateMacros(match[2]);
      validateMacros(match[3]);
      if (name === "deprecatevar" && match[1].toUpperCase() === "TX")
        throw new Error("deprecatevar requires a persistent collection");
      data.effects.push({
        type: name,
        collection: match[1].toUpperCase(),
        name: utf8Bytes(match[2]),
        value: utf8Bytes(match[3]),
      });
    } else if (name === "skipafter") data.skipAfter = arg;
    else if (name === "skip") {
      if (!/^\d+$/.test(arg ?? "")) throw new Error("Invalid skip count");
      data.skip = Number(arg);
    } else if (name === "status") {
      if (!/^[45]\d\d$/.test(arg ?? "")) throw new Error("Unsupported status");
      data.status = Number(arg);
    } else if (name === "capture") data.capture = true;
    else if (name === "msg") {
      validateMacros(arg ?? "");
      data.message = arg;
    } else if (name === "severity") data.severity = arg;
    else if (name === "log") data.log = true;
    else if (name === "nolog") data.log = false;
    else if (name === "auditlog") data.audit = true;
    else if (name === "noauditlog") data.audit = false;
    else if (name === "logdata") {
      validateMacros(arg ?? "");
      data.logdata = utf8Bytes(arg ?? "");
    } else if (name === "tag") data.tags.push(arg);
    else if (name === "multimatch") data.multiMatch = true;
    else if (name === "initcol") {
      const m = /^(ip|global)=([\s\S]+)$/i.exec(arg ?? "");
      if (!m) throw new Error("Unsupported initcol expression");
      validateMacros(m[2]);
      const init = { name: m[1].toUpperCase(), key: m[2] };
      data.initializers.push(init);
      data.effects.push({ type: "initcol", ...init });
    } else if (name === "ctl") {
      const m = /^([a-z]+)=([\s\S]+)$/i.exec(arg ?? "");
      if (!m) throw new Error("Malformed ctl action");
      const option = m[1].toLowerCase(),
        value = m[2];
      const allowed = {
        auditengine: ["On", "Off", "RelevantOnly"],
        ruleengine: ["On", "Off", "DetectionOnly"],
        forcerequestbodyvariable: ["On", "Off"],
        requestbodyprocessor: ["URLENCODED", "JSON", "XML", "MULTIPART"],
        requestbodyaccess: ["On", "Off"],
        responsebodyaccess: ["On", "Off"],
      }[option];
      if (
        allowed
          ? !allowed.includes(value)
          : ![
              "ruleremovebyid",
              "ruleremovebytag",
              "ruleremovetargetbyid",
              "ruleremovetargetbytag",
            ].includes(option)
      )
        throw new Error(`Unsupported ctl ${arg}`);
      if (option === "ruleremovebyid" && !/^\d+(?:-\d+)?$/.test(value))
        throw new Error("Invalid ctl rule ID range");
      if (option.startsWith("ruleremovetarget") && !/^[^;]+;[^;]+$/.test(value))
        throw new Error("Invalid ctl target exclusion");
      data.controls.push({ option, value });
    }
  }
  if (data.transformations.length > 24) throw new Error("Too many transforms");
  return data;
}

/** Compile an entire file; strict mode prevents using a partial CRS policy as a full WAF. */
export interface CompileSecLangOptions extends SecLangSourceOptions {
  now?: () => number;
  requestBodyLimit?: number;
  phraseFiles?: Record<string, string[]>;
  strict?: boolean;
  /** Defer PCRE2 WASM compilation until a regex is first evaluated (after build-time strict validation). */
  lazyRegex?: boolean;
  regexBackend?: SecLangRegexBackend;
  detectors?: InjectionDetectors;
}
export function compileSecLang(
  source,
  {
    phraseFiles = {},
    strict = false,
    lazyRegex = false,
    regexBackend,
    detectors,
    fileName,
    files,
    requestBodyLimit = 2 * 1024 * 1024,
    now = Date.now,
  }: CompileSecLangOptions = {},
) {
  if (
    !Number.isSafeInteger(requestBodyLimit) ||
    requestBodyLimit < 0 ||
    requestBodyLimit > 16_777_216
  )
    throw new Error("Invalid SecLang request body limit");
  const hostRequestBodyLimit = requestBodyLimit;
  const statements = expandSecLangSources(source, { fileName, files });
  phraseFiles = {
    ...Object.fromEntries(
      Object.entries(files ?? {})
        .filter(([name]) => /\.(data|txt|ipset|list)$/.test(name))
        .map(([name, text]) => [
          name,
          text.split(/\r?\n/).filter((line) => line.trim() && !line.trimStart().startsWith("#")),
        ]),
    ),
    ...phraseFiles,
  };
  const resources = new Set();
  if (typeof now !== "function") throw new Error("Invalid SecLang clock");
  const collections = new CollectionStore(now);
  let disposed = false;
  if (regexBackend) {
    const underlying = regexBackend;
    regexBackend = {
      untracked: underlying,
      compile(pattern, options) {
        if (!lazyRegex) {
          const regex = underlying.compile(pattern, options);
          resources.add(regex);
          return regex;
        }
        let compiled: SecLangRegex | undefined;
        let destroyed = false;
        const ensure = () => {
          if (destroyed || disposed) throw new Error("PCRE2 pattern was destroyed");
          if (!compiled) {
            compiled = underlying.compile(pattern, options);
          }
          return compiled;
        };
        const lazy: SecLangRegex = {
          matcher(value) {
            return ensure().matcher(value);
          },
          groupCount() {
            return ensure().groupCount();
          },
          destroy() {
            destroyed = true;
            compiled?.destroy?.();
            compiled = undefined;
          },
        };
        resources.add(lazy);
        return lazy;
      },
    };
  }
  const dispose = () => {
    for (const regex of resources) regex.destroy?.();
    resources.clear();
    collections.clear();
    disposed = true;
  };
  const instructions = [];
  const unsupported = [];
  let prior = null;
  const ids = new Set();
  const defaults = new Map();
  const defaultDecisions = new Map();
  const targetUpdates = [];
  const components = [];
  let unicodeMap = defaultUnicodeMap;
  const settings = {
    engine: "On",
    requestBodyAccess: true,
    responseBodyAccess: true,
    removedIds: [],
  };
  for (const stmt of statements) {
    if (
      [
        "SecRuleEngine",
        "SecRequestBodyAccess",
        "SecResponseBodyAccess",
        "SecRequestBodyLimit",
        "SecRuleRemoveById",
      ].includes(stmt.directive)
    ) {
      try {
        if (stmt.directive === "SecRuleRemoveById") {
          const ranges = stmt.args.flatMap((arg) => arg.split(/\s+/)).filter(Boolean);
          if (!ranges.length || ranges.some((range) => !/^\d+(?:-\d+)?$/.test(range)))
            throw new Error("Invalid static rule ID exclusion");
          settings.removedIds.push(...ranges);
        } else {
          if (stmt.args.length !== 1) throw new Error(`Malformed ${stmt.directive}`);
          const value = stmt.args[0];
          if (stmt.directive === "SecRuleEngine") {
            if (!["On", "Off", "DetectionOnly"].includes(value))
              throw new Error("Invalid SecRuleEngine");
            settings.engine = value;
          } else if (stmt.directive === "SecRequestBodyLimit") {
            if (!/^\d+$/.test(value) || Number(value) > 16_777_216)
              throw new Error("Invalid SecRequestBodyLimit");
            requestBodyLimit =
              Number(value) > 0
                ? Math.min(hostRequestBodyLimit, Number(value))
                : hostRequestBodyLimit;
          } else {
            if (!["On", "Off"].includes(value)) throw new Error(`Invalid ${stmt.directive}`);
            settings[
              stmt.directive === "SecRequestBodyAccess" ? "requestBodyAccess" : "responseBodyAccess"
            ] = value === "On";
          }
        }
      } catch (error) {
        unsupported.push(compilerError(String(error.message), stmt));
      }
      continue;
    }
    if (stmt.directive === "SecUnicodeMapFile") {
      try {
        if (stmt.args.length !== 2 || !/^\d{1,5}$/.test(stmt.args[1]))
          throw new Error("Malformed SecUnicodeMapFile");
        const path = sourcePath(stmt.file ?? "main.conf", stmt.args[0]);
        if (typeof files?.[path] !== "string") throw new Error(`Missing Unicode map: ${path}`);
        unicodeMap = parseUnicodeMap(files[path], Number(stmt.args[1]));
      } catch (error) {
        unsupported.push(compilerError(String(error.message), stmt));
      }
      continue;
    }
    if (stmt.directive === "SecDefaultAction") {
      try {
        if (stmt.args.length !== 1) throw new Error("Malformed SecDefaultAction");
        const list = parseActions(stmt.args[0]);
        const data = compileActionSet(list);
        if (!data.phase || !data.decision || data.id || data.chain)
          throw new Error("SecDefaultAction requires phase and disruptive action without id/chain");
        defaults.set(data.phase, list);
        defaultDecisions.set(data.phase, data.decision);
      } catch (error) {
        unsupported.push(compilerError(String(error.message), stmt));
      }
      continue;
    }
    if (stmt.directive === "SecComponentSignature") {
      if (stmt.args.length !== 1)
        unsupported.push(compilerError("Malformed SecComponentSignature", stmt));
      else components.push(stmt.args[0]);
      continue;
    }
    if (stmt.directive === "SecRuleUpdateTargetById") {
      try {
        if (stmt.args.length !== 2 || !/^\d+$/.test(stmt.args[0]))
          throw new Error("Malformed SecRuleUpdateTargetById");
        // Exclusion-only target lists are valid updates, unlike standalone rule selectors.
        const targets = compileSelector(`TX|${stmt.args[1]}`, regexBackend).slice(1);
        targetUpdates.push({ id: stmt.args[0], targets, statement: stmt });
      } catch (error) {
        unsupported.push(compilerError(String(error.message), stmt));
      }
      continue;
    }
    if (stmt.directive === "SecMarker" && stmt.args.length === 1) {
      instructions.push({ type: "marker", name: stmt.args[0], line: stmt.line });
      prior = null;
      continue;
    }
    if (stmt.directive !== "SecRule" && stmt.directive !== "SecAction") {
      unsupported.push(compilerError(`Unsupported directive: ${stmt.directive}`, stmt));
      prior = null;
      continue;
    }
    try {
      const isAction = stmt.directive === "SecAction";
      const [selectorsText, operatorText, actionText = ""] = stmt.args;
      const selectors = isAction ? [] : compileSelector(selectorsText, regexBackend);
      const operator = isAction
        ? undefined
        : compileOperator(operatorText, phraseFiles, regexBackend, detectors, stmt.file);
      const explicit = parseActions(isAction ? selectorsText : actionText);
      if (
        isAction &&
        (explicit.some(({ name }) => name === "chain" || name === "capture") ||
          prior?.actions.chain)
      )
        throw new Error("SecAction cannot participate in a chain or capture");
      if (
        prior?.actions.chain &&
        explicit.some(({ name }) =>
          [
            "id",
            "phase",
            "deny",
            "block",
            "pass",
            "status",
            "skip",
            "skipafter",
            "msg",
            "tag",
            "severity",
            "logdata",
            "rev",
          ].includes(name),
        )
      )
        throw new Error("Chain child contains an action restricted to the chain starter");
      const explicitPhase = explicit.findLast(({ name }) => name === "phase");
      const phase = explicitPhase
        ? Number(explicitPhase.arg)
        : prior?.actions.chain
          ? prior.actions.phase
          : 2;
      const actions = compileActionSet([...(defaults.get(phase) ?? []), ...explicit]);
      for (const control of actions.controls) {
        if (control.option.startsWith("ruleremovetarget")) {
          const [filter, target] = control.value.split(";");
          control.filter = filter;
          control.selectors = compileSelector(
            `TX|!${target.replace(/^!/, "")}`,
            regexBackend,
          ).slice(1);
        }
      }
      if (actions.decision === "block") {
        const inherited = defaultDecisions.get(phase);
        actions.decision = inherited && inherited !== "block" ? inherited : "deny";
      }
      if (phase === 5 && ["deny", "block"].includes(actions.decision))
        throw new Error("Logging phase cannot use disruptive actions");
      if (isAction && (actions.chain || actions.capture || prior?.actions.chain))
        throw new Error("SecAction cannot participate in a chain or capture");
      const step = {
        type: "rule",
        selectors,
        operator,
        actions,
        unconditional: isAction,
        line: stmt.line,
        file: stmt.file,
      };
      if (prior?.actions.chain) {
        step.actions.phase ??= prior.actions.phase;
        prior.next = step;
      } else {
        if (!actions.id) throw new Error("Root rule requires id");
        actions.phase ??= 2;
        actions.numericId = Number(actions.id);
        if (ids.has(actions.id)) throw new Error(`Duplicate rule id ${actions.id}`);
        ids.add(actions.id);
        instructions.push(step);
      }
      prior = step;
    } catch (error) {
      unsupported.push(compilerError(String(error.message), stmt));
      prior = null;
    }
  }
  for (const update of targetUpdates) {
    const rule = instructions.find((item) => item.type === "rule" && item.actions.id === update.id);
    if (!rule)
      unsupported.push(
        compilerError(`Target update references missing rule ${update.id}`, update.statement),
      );
    else rule.selectors.push(...update.targets);
  }
  // Do not silently execute a truncated/incomplete chain.
  for (const item of instructions.filter((i) => i.type === "rule")) {
    let node = item;
    while (node.actions.chain) {
      if (!node.next) {
        unsupported.push({ line: node.line, reason: "Incomplete chain", rule: item.actions.id });
        item.invalid = true;
        break;
      }
      node = node.next;
    }
  }
  if (unsupported.length && strict) {
    const first = unsupported[0];
    dispose();
    throw new Error(
      `SecLang unsupported at ${first.file ?? "main.conf"}:${first.line}: ${first.reason}`,
    );
  }
  const executable = instructions.filter((item) => !item.invalid);
  settings.removedRanges = settings.removedIds.map(parseIdRange);
  // Markers participate in every phase; keep their original positions for skipAfter.
  const phaseInstructions = new Map(
    [1, 2, 3, 4, 5].map((phase) => [
      phase,
      executable.filter((item) => item.type === "marker" || item.actions.phase === phase),
    ]),
  );
  return {
    instructions: executable,
    phaseInstructions,
    unsupported,
    supportedRules: instructions.filter((item) => item.type === "rule" && !item.invalid).length,
    sourceRules: statements.filter((item) => item.directive === "SecRule").length,
    components,
    requestBodyLimit,
    unicodeMap,
    settings,
    now,
    collections,
    dispose,
    get disposed() {
      return disposed;
    },
  };
}
function transformed(value, transforms, context) {
  return transform(String(value), transforms, context.program.unicodeMap);
}
function values(selector, request, tx, phase, context = {}) {
  if (selector.name === "TX") {
    if (phase >= 2 && context.requestBodyAccess !== false && !context.body)
      values({ name: "REQBODY_ERROR" }, request, tx, phase, context);
    if (selector.key !== undefined && !selector.keyRegex) {
      selector.foldedKey ??= asciiLower(utf8Bytes(selector.key));
      return tx.has(selector.foldedKey)
        ? [[selector.foldedKey, String(tx.get(selector.foldedKey))]]
        : [];
    }
    const entries = [...tx].map(([key, value]) => [key, String(value)]);
    return selector.key === undefined
      ? entries
      : entries.filter(([key]) => selectorKeyMatches(selector, key));
  }
  context.url ??= new URL(request.url);
  context.headers ??= new Headers(request.headers ?? {});
  context.target ??=
    request.rawTarget ?? (/^https?:\/\/[^/?#]+([^#]*)/i.exec(request.url)?.[1] || "/");
  const target = context.target;
  if (!context.targetParts) {
    const question = target.indexOf("?");
    context.targetParts = {
      rawPath: question < 0 ? target : target.slice(0, question),
      query: question < 0 ? "" : target.slice(question + 1),
    };
  }
  const { rawPath, query } = context.targetParts;
  context.filename ??= utf8Bytes(rawPath).replace(/%([\da-f]{2})/gi, (_all, hex) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
  const headers = context.headers;
  let entries = [];
  context.getArgs ??= formEntries(query);
  const getArgs = context.getArgs;
  if (context.processor === undefined || context.processor === null)
    context.defaultBodyProcessor ??= bodyProcessor(headers);
  const processor = context.processor ?? context.defaultBodyProcessor;
  if (phase >= 2 && context.requestBodyAccess !== false && !context.body) {
    context.bodyParseError = false;
    context.bodyErrorMessage = "";
    try {
      context.body = parseBody(
        request.bodyText ?? "",
        headers,
        processor,
        request.bodyBytes,
        context.program?.requestBodyLimit,
      );
    } catch {
      context.bodyParseError = true;
      context.bodyErrorMessage = `Invalid ${processor || "raw"} request body`;
      context.body = { args: [], files: [], partHeaders: [], xml: undefined };
    }
  }
  const body = phase >= 2 && context.requestBodyAccess !== false ? context.body : undefined;
  const postArgs = body?.args ?? [];
  // Immutable request collections are materialized only when selected. Never cache TX,
  // ctl-dependent body collections or matched variables: actions can change them mid-chain.
  switch (selector.name) {
    case "REQUEST_METHOD":
      entries = [["REQUEST_METHOD", request.method]];
      break;
    case "REQUEST_URI":
      entries = [["REQUEST_URI", target]];
      break;
    case "REQUEST_URI_RAW":
      entries = [["REQUEST_URI_RAW", target]];
      break;
    case "REQUEST_FILENAME":
      entries = [["REQUEST_FILENAME", context.filename]];
      break;
    case "REQUEST_BASENAME":
      context.basename ??= context.filename.split("/").pop();
      entries = [["REQUEST_BASENAME", context.basename]];
      break;
    case "REQUEST_PROTOCOL":
      if (!request.protocol)
        throw new Error("SecLang REQUEST_PROTOCOL requires trusted transport metadata");
      entries = [["REQUEST_PROTOCOL", request.protocol]];
      break;
    case "REQUEST_LINE":
      if (!request.requestLine && !request.protocol)
        throw new Error("SecLang REQUEST_LINE requires trusted transport metadata");
      entries = [
        ["REQUEST_LINE", request.requestLine ?? `${request.method} ${target} ${request.protocol}`],
      ];
      break;
    case "REMOTE_ADDR":
      if (!request.remoteAddr)
        throw new Error("SecLang REMOTE_ADDR requires a trusted client address");
      entries = [["REMOTE_ADDR", request.remoteAddr]];
      break;
    case "UNIQUE_ID":
      entries = [["UNIQUE_ID", context.uniqueId]];
      break;
    case "REQBODY_PROCESSOR":
      entries = [["REQBODY_PROCESSOR", processor]];
      break;
    case "REQBODY_ERROR":
    case "REQBODY_PROCESSOR_ERROR":
      entries = phase >= 2 ? [[selector.name, context.bodyParseError ? "1" : "0"]] : [];
      break;
    case "REQBODY_ERROR_MSG":
    case "REQBODY_PROCESSOR_ERROR_MSG":
      entries = phase >= 2 ? [[selector.name, context.bodyErrorMessage ?? ""]] : [];
      break;
    case "MULTIPART_STRICT_ERROR":
      entries =
        phase >= 2
          ? [[selector.name, processor === "MULTIPART" && context.bodyParseError ? "1" : "0"]]
          : [];
      break;
    case "INBOUND_DATA_ERROR":
      entries =
        phase >= 2
          ? [
              [
                selector.name,
                (request.bodyBytes?.length ?? utf8Encoder.encode(request.bodyText ?? "").length) >
                context.program.requestBodyLimit
                  ? "1"
                  : "0",
              ],
            ]
          : [];
      break;
    case "FILES":
      entries = (body?.files ?? []).map((file) => [file.name, file.filename]);
      break;
    case "FILES_NAMES":
      entries = (body?.files ?? []).map((file) => [file.name, file.name]);
      break;
    case "FILES_COMBINED_SIZE":
      entries = body
        ? [["FILES_COMBINED_SIZE", String(body.files.reduce((n, file) => n + file.size, 0))]]
        : [];
      break;
    case "MULTIPART_PART_HEADERS":
      entries = body?.partHeaders ?? [];
      break;
    case "XML":
      return body?.xml
        ? xmlValues(body.xml, selector.key ?? "/*").map(([k, v]) => [k, utf8Bytes(v)])
        : [];
    case "RESPONSE_BODY":
      entries =
        phase >= 4 &&
        context.responseBodyAccess !== false &&
        (request.responseBody !== undefined || request.responseBodyBytes !== undefined)
          ? [
              [
                "RESPONSE_BODY",
                request.responseBodyBytes
                  ? fromOctets(request.responseBodyBytes)
                  : utf8Bytes(request.responseBody),
              ],
            ]
          : [];
      break;
    case "RESPONSE_STATUS":
      entries =
        phase >= 3 && request.responseStatus !== undefined
          ? [["RESPONSE_STATUS", String(request.responseStatus)]]
          : [];
      break;
    case "RESPONSE_HEADERS":
      if (phase >= 3) {
        if (context.responseHeaderSource !== request.responseHeaders) {
          context.responseHeaderSource = request.responseHeaders;
          context.responseHeaderEntries = [
            ...new Headers(request.responseHeaders ?? {}).entries(),
          ].map(([k, v]) => [k, utf8Bytes(v)]);
        }
        entries = context.responseHeaderEntries;
      } else entries = [];
      break;
    case "MATCHED_VARS":
      entries = [...(context.matchedVars ?? [])];
      break;
    case "IP":
    case "GLOBAL":
      entries = [...(context.collections?.get(selector.name) ?? [])].map(([k, v]) => [
        k,
        String(v),
      ]);
      break;
    case "QUERY_STRING":
      entries = [["QUERY_STRING", query]];
      break;
    case "REQUEST_HEADERS":
      context.headerEntries ??= [...headers.entries()];
      entries = context.headerEntries;
      break;
    case "REQUEST_HEADERS_NAMES":
      context.headerNames ??= [...headers.keys()].map((v) => [v, v]);
      entries = context.headerNames;
      break;
    case "REQUEST_BODY":
      entries =
        phase >= 2 &&
        context.requestBodyAccess !== false &&
        ((processor !== "" && processor !== "MULTIPART") || context.forceBody)
          ? [
              [
                "REQUEST_BODY",
                request.bodyBytes
                  ? fromOctets(request.bodyBytes)
                  : utf8Bytes(request.bodyText ?? ""),
              ],
            ]
          : [];
      break;
    case "ARGS":
      if (!postArgs.length) entries = getArgs;
      else if (!getArgs.length) entries = postArgs;
      else {
        context.argsEntries ??= [...getArgs, ...postArgs];
        entries = context.argsEntries;
      }
      break;
    case "ARGS_GET":
      entries = getArgs;
      break;
    case "ARGS_POST":
      entries = postArgs;
      break;
    case "ARGS_GET_NAMES":
      context.getArgsNames ??= getArgs.map(([k]) => [k, k]);
      entries = context.getArgsNames;
      break;
    case "ARGS_POST_NAMES":
      context.postArgsNames ??= postArgs.map(([k]) => [k, k]);
      entries = context.postArgsNames;
      break;
    case "ARGS_COMBINED_SIZE": {
      let size = 0;
      for (let i = 0; i < getArgs.length; i++) size += getArgs[i][0].length + getArgs[i][1].length;
      for (let i = 0; i < postArgs.length; i++)
        size += postArgs[i][0].length + postArgs[i][1].length;
      entries = [["ARGS_COMBINED_SIZE", String(size)]];
      break;
    }
    case "REQUEST_BODY_LENGTH":
      entries =
        phase >= 2
          ? [
              [
                "REQUEST_BODY_LENGTH",
                String(
                  request.bodyBytes?.length ?? utf8Encoder.encode(request.bodyText ?? "").length,
                ),
              ],
            ]
          : [];
      break;
    case "MATCHED_VAR":
      entries = context.matchedValue === undefined ? [] : [["MATCHED_VAR", context.matchedValue]];
      break;
    case "MATCHED_VAR_NAME":
      entries =
        context.matchedName === undefined ? [] : [["MATCHED_VAR_NAME", context.matchedName]];
      break;
    case "ARGS_NAMES":
      if (!postArgs.length) {
        context.getArgsNames ??= getArgs.map(([k]) => [k, k]);
        entries = context.getArgsNames;
      } else {
        context.argsNames ??= [...getArgs, ...postArgs].map(([k]) => [k, k]);
        entries = context.argsNames;
      }
      break;
    case "REQUEST_COOKIES":
    case "REQUEST_COOKIES_NAMES":
      if (!context.cookieEntries) {
        const rawCookie = headers.get("cookie");
        context.cookieEntries = rawCookie
          ? rawCookie
              .split(/;\s*/)
              .filter(Boolean)
              .map((part) => {
                const at = part.indexOf("=");
                return [
                  at < 0 ? part.trim() : part.slice(0, at).trim(),
                  at < 0 ? "" : part.slice(at + 1),
                ];
              })
          : [];
      }
      if (selector.name === "REQUEST_COOKIES") {
        entries = context.cookieEntries;
      } else {
        context.cookieNames ??= context.cookieEntries.map(([k]) => [k, k]);
        entries = context.cookieNames;
      }
      break;
  }
  if (selector.key !== undefined)
    entries = entries.filter(([k]) => selectorKeyMatches(selector, k));
  if (!BYTE_COLLECTIONS.has(selector.name) && selector.name !== "RESPONSE_HEADERS")
    entries = entries.map(([key, value]) => [key, utf8Bytes(String(value))]);
  return entries;
}
function selectorKeyMatches(selector, key) {
  if (selector.key === undefined) return true;
  if (selector.keyRegex) return selector.keyRegex.matcher(key).find();
  selector.foldedKey ??= asciiLower(utf8Bytes(selector.key));
  return asciiLower(key) === selector.foldedKey;
}
function getValues(selectors, request, tx, phase, context) {
  if (context.excludedTargets?.length) selectors = [...selectors, ...context.excludedTargets];
  const hasExclusions = selectors.some((item) => item.negative);
  const selected = [];
  for (const item of selectors) {
    if (item.negative) continue;
    let entries = values(item, request, tx, phase, context);
    if (hasExclusions)
      entries = entries.filter(([key]) => {
        const excluded = selectors.some(
          (negative) =>
            negative.negative && negative.name === item.name && selectorKeyMatches(negative, key),
        );
        return !excluded;
      });
    if (item.count) selected.push([item.name, String(entries.length)]);
    else
      for (const [key, value] of entries)
        selected.push([key === item.name ? key : `${item.name}:${key}`, String(value)]);
  }
  return selected;
}

function integer(value) {
  const match = /^[\t\n\v\f\r ]*([+-]?\d+)/.exec(String(value));
  const number = match ? Number(match[1]) : 0;
  return Number.isInteger(number) && number >= -2147483648 && number <= 2147483647 ? number : 0;
}
function compares(value, condition, tx, context) {
  const { op, regex } = condition;
  const operand = condition.dynamic ? macro(condition.operand, tx, context) : condition.operand;
  switch (op) {
    case "streq":
      return value === operand;
    case "contains":
      return value.includes(operand);
    case "beginswith":
      return value.startsWith(operand);
    case "endswith":
      return value.endsWith(operand);
    case "within":
      return operand.includes(value);
    case "unconditionalmatch":
      return true;
    case "detectsqli":
      return condition.detectors.sqli(value).matched;
    case "detectxss":
      return condition.detectors.xss(value);
    case "validateurlencoding":
      return /%(?![\da-f]{2})/i.test(value);
    case "validatebyterange":
      return [...octets(value)].some(
        (n) => !condition.ranges.some(([start, end]) => n >= start && n <= end),
      );
    case "validateutf8encoding": {
      try {
        utf8FatalDecoder.decode(octets(value));
        return false;
      } catch {
        return true;
      }
    }
    case "ipmatchfromfile":
    case "ipmatch": {
      try {
        const address = ipaddr.parse(value);
        return condition.networks.some(
          ([network, bits]) => network.kind() === address.kind() && address.match(network, bits),
        );
      } catch {
        return false;
      }
    }
    case "rx":
      return regex.matcher(value).find();
    case "pm":
    case "pmfromfile":
      return condition.phraseMatcher.test(asciiLower(value));
    case "eq":
      return integer(value) === integer(operand);
    case "lt":
      return integer(value) < integer(operand);
    case "le":
      return integer(value) <= integer(operand);
    case "gt":
      return integer(value) > integer(operand);
    case "ge":
      return integer(value) >= integer(operand);
  }
  return false;
}
function match(step, request, tx, phase, context) {
  if (step.unconditional) {
    applyEffects(step.actions, tx, context);
    return true;
  }
  const source = getValues(step.selectors, request, tx, phase, context);
  context.matchedVars.length = 0;
  if (!source.length) return false;
  let matched = false;
  const transforms = step.actions.transformations;
  const hasTransforms = transforms.length > 0;
  const isMulti = Boolean(step.actions.multiMatch);
  const op = step.operator;
  const evaluate = (name, value) => {
    let dynamicRegex = null;
    if (op.op === "rx" && op.dynamic)
      dynamicRegex = op.dynamicRegexBackend.compile(macro(op.operand, tx, context), {
        binary: true,
      });
    const condition = dynamicRegex ? { ...op, regex: dynamicRegex } : op;
    try {
      let result = false;
      let matcher = null;
      let capture: string | undefined;
      if (step.actions.capture && op.op === "rx") {
        matcher = condition.regex.matcher(value);
        result = matcher.find();
      } else if (op.op === "detectsqli") {
        const detected = op.detectors.sqli(value);
        result = detected.matched;
        capture = detected.fingerprint;
      } else if (op.op === "pm" || op.op === "pmfromfile") {
        const lower = asciiLower(value);
        if (step.actions.capture) {
          capture = op.phraseMatcher.match(lower, value);
          result = capture !== undefined;
        } else {
          result = op.phraseMatcher.test(lower);
        }
      } else result = compares(value, condition, tx, context);
      if (result && matcher) {
        for (let i = 0; i <= condition.regex.groupCount(); i++) {
          const group = matcher.group(i);
          if (group !== null) tx.set(String(i), group);
        }
      }
      if (result && step.actions.capture && capture !== undefined) tx.set("0", capture);
      if (op.negated ? !result : result) {
        matched = true;
        context.matchedValue = value;
        context.matchedName = name;
        context.matchedVars.push([name, value]);
        applyEffects(step.actions, tx, context);
      }
    } finally {
      dynamicRegex?.destroy?.();
    }
  };
  for (let s = 0; s < source.length; s++) {
    const [name, raw] = source[s];
    if (!isMulti) {
      evaluate(name, hasTransforms ? transformed(raw, transforms, context) : raw);
      continue;
    }
    let value = raw;
    evaluate(name, value);
    for (let t = 0; t < transforms.length; t++) {
      const next = transformed(value, [transforms[t]], context);
      if (next !== value) evaluate(name, next);
      value = next;
    }
  }
  return matched;
}
function macroVariable(name) {
  const dot = name.indexOf(".");
  const collection = (dot < 0 ? name : name.slice(0, dot)).toUpperCase();
  if (!VARIABLES.has(collection) || (dot >= 0 && dot === name.length - 1)) return undefined;
  return { name: collection, key: dot < 0 ? undefined : name.slice(dot + 1) };
}
function validateMacros(value) {
  if (!value.includes("%{")) return;
  for (const match of value.matchAll(/%\{([^}]+)\}/g)) {
    if (
      !/^(?:(?:tx|ip|global)\.[\w.-]+|rule\.(?:id|msg|severity)|matched_var|matched_var_name|remote_addr|request_line|request_headers\.[^}]+|args\.[^}]+)$/i.test(
        match[1],
      ) &&
      !macroVariable(match[1])
    )
      throw new Error(`Unsupported macro ${match[1]}`);
  }
  if (value.replace(/%\{[^}]+\}/g, "").includes("%{")) throw new Error("Malformed macro");
}
function macro(value, tx, context = {}) {
  if (!value.includes("%{")) return value;
  return value.replace(/%\{([^}]+)\}/gi, (_, name) => {
    const key = asciiLower(name);
    if (key.startsWith("tx.")) return String(tx.get(key.slice(3)) ?? "");
    if (/^(ip|global)\./.test(key)) {
      const at = key.indexOf(".");
      return String(
        context.collections?.get(key.slice(0, at).toUpperCase())?.get(key.slice(at + 1)) ?? "",
      );
    }
    if (key.startsWith("rule.")) return String(context.rule?.[key.slice(5)] ?? "");
    if (key === "matched_var") return context.matchedValue ?? "";
    if (key === "matched_var_name") return context.matchedName ?? "";
    if (key === "remote_addr") {
      if (!context.request.remoteAddr)
        throw new Error("REMOTE_ADDR macro requires a trusted client address");
      return context.request.remoteAddr;
    }
    if (key === "request_line")
      return (
        values({ name: "REQUEST_LINE" }, context.request, tx, context.phase, context)[0]?.[1] ?? ""
      );
    if (key.startsWith("request_headers."))
      return new Headers(context.request.headers).get(name.slice(16)) ?? "";
    if (key.startsWith("args."))
      return (
        values(
          { name: "ARGS", key: name.slice(5) },
          context.request,
          tx,
          context.phase,
          context,
        )[0]?.[1] ?? ""
      );
    const selector = macroVariable(name);
    if (selector)
      return values(selector, context.request, tx, context.phase, context)[0]?.[1] ?? "";
    throw new Error(`Unsupported macro ${name}`);
  });
}
function updateState(changes, tx, context) {
  for (const change of changes) {
    const store = change.collection === "TX" ? tx : context.collections?.get(change.collection);
    if (!store) throw new Error(`Collection ${change.collection} has not been initialized`);
    const name = asciiLower(macro(change.name, tx, context));
    if (name.length > 4096) throw new Error("TX variable name exceeds limit");
    if (!store.has(name) && store.size >= (change.collection === "TX" ? 4096 : 1024))
      throw new Error("SecLang collection variable limit exceeded");
    if (change.remove) {
      store.delete(name);
      const record =
        change.collection === "TX"
          ? context.txRecord
          : context.collectionRecords?.get(change.collection);
      record?.expires.delete(name);
      record?.decay.delete(name);
      continue;
    }
    const evaluated = macro(change.value, tx, context);
    const record =
      change.collection === "TX"
        ? context.txRecord
        : context.collectionRecords?.get(change.collection);
    if (record && !store.has(name)) record.decay.set(name, context.program.now());
    const arithmetic = /^([+-])([\s\S]*)$/.exec(evaluated);
    if (arithmetic) {
      const current = integer(store.get(name) ?? 0);
      const delta = integer(arithmetic[2]) * (arithmetic[1] === "+" ? 1 : -1);
      if (
        !Number.isSafeInteger(current + delta) ||
        current + delta < -2147483648 ||
        current + delta > 2147483647
      )
        throw new Error("TX arithmetic overflow");
      store.set(name, current + delta);
    } else store.set(name, evaluated);
  }
}
function idMatches(id, range) {
  const [start, end = start] = range.split("-").map(Number);
  return Number(id) >= start && Number(id) <= end;
}
function initializeCollections(actions, program, tx, context) {
  for (const init of actions.initializers) {
    const key = `${init.name}:${macro(init.key, tx, context)}`;
    const record = program.collections.get(key);
    context.collectionRecords.set(init.name, record);
    context.collections.set(init.name, record.values);
  }
}
function applyEffects(actions, tx, context) {
  for (const effect of actions.effects) {
    if (effect.type === "initcol") {
      initializeCollections({ initializers: [effect] }, context.program, tx, context);
      continue;
    }
    if (effect.type === "setvar") {
      updateState([effect], tx, context);
      continue;
    }
    const record =
      effect.collection === "TX"
        ? context.txRecord
        : context.collectionRecords.get(effect.collection);
    if (!record) throw new Error(`Collection ${effect.collection} has not been initialized`);
    const name = asciiLower(macro(effect.name, tx, context));
    if (!record.values.has(name)) continue;
    const value = macro(effect.value, tx, context),
      now = context.program.now();
    if (effect.type === "expirevar") {
      if (!/^\d+$/.test(value) || Number(value) > 31_536_000)
        throw new Error("Invalid expirevar interval");
      record.expires.set(name, now + Number(value) * 1000);
      context.program.collections.refresh(record);
    } else {
      const match = /^(\d+)\/(\d+)$/.exec(value);
      if (!match || Number(match[1]) < 1 || Number(match[2]) < 1 || Number(match[2]) > 31_536_000)
        throw new Error("Invalid deprecatevar rate");
      const interval = Number(match[2]) * 1000,
        prior = record.decay.get(name) ?? now,
        steps = Math.max(0, Math.floor((now - prior) / interval));
      const current = Number(record.values.get(name));
      if (!Number.isFinite(current)) throw new Error("deprecatevar requires a numeric value");
      record.values.set(name, Math.max(0, current - steps * Number(match[1])));
      record.decay.set(name, prior + steps * interval);
    }
  }
}
function controls(actions, _program, _tx, context) {
  for (const control of actions.controls) {
    const { option, value } = control;
    if (option === "ruleremovebyid") {
      context.removedIds.push(value);
      context.removedRanges.push(parseIdRange(value));
    } else if (option === "ruleremovebytag") context.removedTags.add(value);
    else if (option.startsWith("ruleremovetarget")) context.targetRemovals.push(control);
    else if (option === "requestbodyprocessor") {
      context.processor = value;
      context.body = undefined;
      context.postArgsNames = undefined;
      context.argsEntries = undefined;
      context.argsNames = undefined;
    } else if (option === "forcerequestbodyvariable") context.forceBody = value === "On";
    else if (option === "ruleengine") context.engine = value;
    else if (option === "auditengine") context.auditEngine = value;
    else if (option === "requestbodyaccess") context.requestBodyAccess = value === "On";
    else if (option === "responsebodyaccess") context.responseBodyAccess = value === "On";
  }
}
/** Evaluate request phases with per-transaction TX state and deterministic order. */
export interface SecLangTransaction {
  tx: Map<string, string | number>;
  matchedVars: [string, string][];
  uniqueId: string;
  [key: string]: unknown;
}
export interface ExecuteSecLangOptions {
  tx?: Record<string, string | number>;
  phases?: number[];
  anomalyThreshold?: number;
  shouldSkip?: ((id: string) => boolean) | undefined;
  transaction?: SecLangTransaction;
}
export function executeSecLang(
  program,
  request,
  {
    tx: inputTx = {},
    phases = [1, 2],
    anomalyThreshold,
    shouldSkip,
    transaction,
  }: ExecuteSecLangOptions = {},
) {
  if (program.disposed) throw new Error("Cannot execute a disposed SecLang program");
  if (program.unsupported.length)
    throw new Error("Cannot run an incompletely compiled SecLang policy");
  if (!request || typeof request.url !== "string" || typeof request.method !== "string")
    throw new TypeError("SecLang VM requires a URL and method");
  if (
    phases.some(
      (phase, i) =>
        ![1, 2, 3, 4, 5].includes(phase) ||
        phase <= (i ? phases[i - 1] : (transaction?.phase ?? 0)),
    )
  )
    throw new Error("SecLang phases must execute once in ascending order");
  if (
    transaction?.request &&
    (transaction.request.url !== request.url || transaction.request.method !== request.method)
  )
    throw new Error("SecLang transaction request changed");
  const tx =
    transaction?.tx ??
    new Map(
      Object.entries(inputTx).map(([k, v]) => [
        asciiLower(utf8Bytes(k)),
        typeof v === "string" ? utf8Bytes(v) : v,
      ]),
    );
  const matched = [];
  const events = [];
  const context: SecLangTransaction = transaction ?? {
    tx,
    matchedVars: [],
    uniqueId: crypto.randomUUID(),
    removedIds: [...program.settings.removedIds],
    removedRanges: [...program.settings.removedRanges],
    removedTags: new Set(),
    targetRemovals: [],
    collections: new Map(),
    collectionRecords: new Map(),
    txRecord: collectionRecord(program.now(), tx),
    engine: program.settings.engine,
    requestBodyAccess: program.settings.requestBodyAccess,
    responseBodyAccess: program.settings.responseBodyAccess,
  };
  context.request = request;
  context.program = program;
  program.collections.refresh(context.txRecord);
  for (const record of context.collectionRecords.values()) program.collections.refresh(record);
  let blocked = false;
  let status = 403;
  const ruleInfo = { id: undefined, msg: undefined, severity: undefined };
  for (const phase of phases) {
    if (blocked && phase !== 5) continue;
    context.phase = phase;
    if (
      phase >= 2 &&
      context.engine !== "Off" &&
      context.requestBodyAccess !== false &&
      !context.body
    )
      values({ name: "REQBODY_ERROR" }, request, tx, phase, context);
    let skipUntil: string | undefined;
    let skip = 0;
    for (const rule of program.phaseInstructions.get(phase)) {
      if (rule.type === "marker") {
        if (skipUntil === rule.name) skipUntil = undefined;
        continue;
      }
      if (skipUntil) {
        if (rule.actions.phase === phase && rule.actions.id === skipUntil) skipUntil = undefined;
        continue;
      }
      if (rule.actions.phase !== phase) continue;
      if (skip > 0) {
        skip--;
        continue;
      }
      if (shouldSkip?.(rule.actions.id)) continue;
      if (context.engine === "Off") break;
      if (context.removedRanges.length) {
        const nid = rule.actions.numericId;
        let isRemoved = false;
        for (let r = 0; r < context.removedRanges.length; r++) {
          const [start, end] = context.removedRanges[r];
          if (nid >= start && nid <= end) {
            isRemoved = true;
            break;
          }
        }
        if (isRemoved) continue;
      }
      if (context.removedTags.size && rule.actions.tags.length) {
        let isRemoved = false;
        for (let t = 0; t < rule.actions.tags.length; t++) {
          if (context.removedTags.has(rule.actions.tags[t])) {
            isRemoved = true;
            break;
          }
        }
        if (isRemoved) continue;
      }
      if (context.targetRemovals.length) {
        context.excludedTargets = context.targetRemovals
          .filter((control) =>
            control.option.endsWith("byid")
              ? idMatches(rule.actions.id, control.filter)
              : rule.actions.tags.includes(control.filter),
          )
          .flatMap((control) => control.selectors);
      } else {
        context.excludedTargets = undefined;
      }
      ruleInfo.id = rule.actions.id;
      ruleInfo.msg = rule.actions.message;
      ruleInfo.severity = rule.actions.severity;
      context.rule = ruleInfo;
      let current = rule,
        allMatched = true;
      while (current) {
        const effectivePhase = current.actions.phase ?? rule.actions.phase;
        if (effectivePhase !== phase || !match(current, request, tx, phase, context)) {
          allMatched = false;
          break;
        }
        current = current.next;
      }
      if (!allMatched) continue;
      matched.push(rule.actions.id);
      const message = macro(utf8Bytes(rule.actions.message ?? ""), tx, context);
      const logdata = macro(rule.actions.logdata ?? "", tx, context);
      events.push({
        id: rule.actions.id,
        phase,
        log: rule.actions.log,
        audit: rule.actions.audit && context.auditEngine !== "Off",
        message: message.slice(0, 4096),
        logdata: logdata.slice(0, 4096),
        truncated: message.length > 4096 || logdata.length > 4096,
        severity: rule.actions.severity,
        tags: rule.actions.tags,
      });
      current = rule;
      while (current) {
        controls(current.actions, program, tx, context);
        if (current.actions.skipAfter) skipUntil = current.actions.skipAfter;
        if (current.actions.skip) skip = current.actions.skip;
        if (
          context.engine !== "DetectionOnly" &&
          ["deny", "block"].includes(current.actions.decision)
        )
          blocked = true;
        if (current.actions.status) status = current.actions.status;
        current = current.next;
      }
      if (blocked && phase !== 5) break;
    }
  }
  if (context.auditEngine === "Off") for (const event of events) event.audit = false;
  const score = Number(
    tx.get(
      phases.some((phase) => phase >= 3)
        ? "blocking_outbound_anomaly_score"
        : "blocking_inbound_anomaly_score",
    ) ??
      tx.get("inbound_anomaly_score") ??
      tx.get("anomaly_score") ??
      0,
  );
  if (
    context.engine !== "DetectionOnly" &&
    anomalyThreshold !== undefined &&
    score >= anomalyThreshold
  )
    blocked = true;
  return {
    blocked,
    status: blocked ? status : 200,
    matched,
    events,
    score,
    tx: Object.fromEntries(tx),
    transaction: context,
  };
}
