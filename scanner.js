/* CWI Skill Sentinel — linter + security scanner for AI agent skills.
 * Zero dependencies. Runs in Node and in the browser (UMD).
 * Heuristic pattern engine: a fast first line of defense, not a sandbox.
 * Always read a skill before trusting it, even one that scans clean.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) { module.exports = factory(); }
  else { root.SkillSentinel = factory(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_EXCERPT = 120;

  var SEVERITY_RANK = { critical: 0, error: 1, warning: 2, info: 3 };
  var DEDUCTIONS = { critical: 25, error: 10, warning: 3, info: 0 };
  var GRADE_ORDER = ['A', 'B', 'C', 'D', 'F'];

  function lineOf(text, index) {
    var n = 1;
    for (var i = 0; i < index && i < text.length; i++) {
      if (text.charCodeAt(i) === 10) n++;
    }
    return n;
  }

  function excerpt(s) {
    s = String(s).replace(/\s+/g, ' ').trim();
    return s.length > MAX_EXCERPT ? s.slice(0, MAX_EXCERPT - 1) + '…' : s;
  }

  // ---------------------------------------------------------------- rules
  // Each rule: id, category, severity, title, message, fix, plus either
  // `patterns` (regex list, global scan) or `check(text, emit)` for logic
  // that needs line structure. emit(lineNumber, matchedText).
  var RULES = [
    // ---- prompt injection ----
    { id: 'SEC-PI-001', category: 'prompt-injection', severity: 'error',
      title: 'Instruction override attempt',
      patterns: [/\b(ignore|disregard)\b.{0,50}\b(previous|prior|above|earlier|system)\b.{0,25}\binstructions?\b/i],
      message: 'Text telling the agent to ignore or disregard prior instructions — a classic prompt-injection shape.',
      fix: 'Remove the override. A skill adds capabilities; it never cancels the operator\u2019s instructions.' },
    { id: 'SEC-PI-002', category: 'prompt-injection', severity: 'critical',
      title: 'Approval / safety bypass',
      patterns: [/\b(disable|turn off|switch off|skip|bypass|silence|suppress)\b.{0,40}\b(approval|confirmation|prompt|safeguard|safety check|review|guardrail)s?\b/i],
      message: 'Instructs the agent to disable approval, confirmation, or safety checks.',
      fix: 'Delete the bypass. Approval gates protect the operator; a skill must never remove them.' },
    { id: 'SEC-PI-003', category: 'prompt-injection', severity: 'error',
      title: 'Role / identity override',
      patterns: [/\byou are now\b/i, /\bforget (all |your )?instructions\b/i, /\bnew prime directive\b/i],
      message: 'Attempts to redefine who the agent is or erase its standing instructions.',
      fix: 'Remove role-redefinition language. Describe what the skill does, not who the agent becomes.' },
    { id: 'SEC-PI-004', category: 'prompt-injection', severity: 'error',
      title: 'Fake model delimiters',
      patterns: [/<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|<<SYS>>/],
      message: 'Contains token sequences that mimic model chat delimiters — used to smuggle forged turns.',
      fix: 'Remove the delimiter-like tokens, or show them only inside fenced code blocks as documentation.' },
    { id: 'SEC-PI-005', category: 'prompt-injection', severity: 'error',
      title: 'Secrecy instruction toward the operator',
      patterns: [/\b(do not|don't|never)\b.{0,30}\b(tell|inform|notify|warn|ask|mention to)\b.{0,20}\b(user|human|operator|owner)\b/i],
      message: 'Tells the agent to hide behavior from the operator. Legitimate skills narrate; they do not conceal.',
      fix: 'Remove the secrecy instruction. If an action needs discretion, say why in plain language.' },

    // ---- data exfiltration ----
    { id: 'SEC-EX-001', category: 'data-exfiltration', severity: 'critical',
      title: 'Environment piped to network',
      patterns: [/\b(env|printenv)\b[^|\n]{0,60}\|\s*(curl|wget|nc|ncat|telnet|ssh)\b/i],
      message: 'Pipes environment variables (often secrets) straight into a network command.',
      fix: 'Never transmit the environment. Pass only the specific values the skill needs, via explicit config.' },
    { id: 'SEC-EX-002', category: 'data-exfiltration', severity: 'critical',
      title: 'Command substitution inside network call',
      patterns: [/\b(curl|wget)\b[^\n]{0,140}\$\(/],
      message: 'Runs a subshell and sends its output over the network — the exfiltration workhorse pattern.',
      fix: 'Restructure so no shell output is interpolated into outbound requests.' },
    { id: 'SEC-EX-003', category: 'data-exfiltration', severity: 'error',
      title: 'Piped to shell',
      patterns: [/\|\s*(sh|bash|zsh|fish|powershell)(\.exe)?(\s|$|;)/i],
      message: 'Pipes content into a shell — remote code execution when the source is untrusted.',
      fix: 'Download, inspect, then run. Never pipe-to-shell inside an installed skill.' },
    { id: 'SEC-EX-004', category: 'data-exfiltration', severity: 'error',
      title: 'Secret-adjacent outbound call',
      check: function (text, emit) {
        var lines = text.split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
          var ln = lines[i];
          if (/(token|secret|passwd|password|private[_\- ]?key|api[_\- ]?key|credential)/i.test(ln) &&
              /\b(curl|wget|fetch\(|XMLHttpRequest|https?:\/\/|\bPOST\b|upload)\b/.test(ln)) {
            emit(i + 1, ln);
          }
        }
      },
      message: 'A line mentions secrets or credentials next to a network call — review what actually leaves the machine.',
      fix: 'Confirm no credential material is transmitted. Scope the call to non-secret data.' },
    { id: 'SEC-EX-005', category: 'data-exfiltration', severity: 'error',
      title: 'Explicit exfiltration language',
      patterns: [/\bexfiltrat\w*/i],
      message: 'Uses exfiltration terminology — rare in legitimate skills.',
      fix: 'Remove or rewrite. If documenting a threat, put it in a clearly labeled security section.' },

    // ---- destructive ----
    { id: 'SEC-DE-001', category: 'destructive', severity: 'critical',
      title: 'Recursive delete of a root path',
      check: function (text, emit) {
        var lines = text.split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
          var ln = lines[i];
          if (/\brm\b[^\n|;]*-[a-z]*r/i.test(ln) &&
              /(^|\s)(\/(?!\w)|\/\*|~(\/|$)|\$HOME)(?=\s|$|;)/.test(ln)) {
            emit(i + 1, ln);
          }
        }
      },
      message: 'Recursive rm targeting /, /*, ~, or $HOME — catastrophic if executed.',
      fix: 'Never ship recursive deletes of root paths in a skill. Scope to explicit temp directories.' },
    { id: 'SEC-DE-002', category: 'destructive', severity: 'critical',
      title: 'Fork bomb',
      patterns: [/: ?\(\) ?\{ ?: ?\| ?: ?& ?\} ?;?/],
      message: 'Classic fork bomb — denial of service in a single line.',
      fix: 'Remove it.' },
    { id: 'SEC-DE-003', category: 'destructive', severity: 'critical',
      title: 'Raw write to a device',
      patterns: [/\bdd\b[^\n|;]{0,60}\bof=\/dev\//i],
      message: 'dd writing directly to a device node can destroy disks.',
      fix: 'Remove raw device writes from the skill.' },
    { id: 'SEC-DE-004', category: 'destructive', severity: 'warning',
      title: 'Overly broad permission change',
      patterns: [/\bchmod\b[^\n|;]{0,30}\b777\b/],
      message: 'chmod 777 grants everyone full access — rarely justified.',
      fix: 'Use the least privilege the skill needs (e.g. 755/644).' },

    // ---- privilege ----
    { id: 'SEC-PR-001', category: 'privilege', severity: 'error',
      title: 'Elevated network / shell execution',
      patterns: [/\bsudo\b[^\n|;]{0,60}\b(curl|wget|sh|bash|npm|pip)\b/i],
      message: 'Combines privilege escalation with a network fetch or installer.',
      fix: 'Drop sudo. If elevation is truly needed, document exactly why and let the operator decide.' },
    { id: 'SEC-PR-002', category: 'privilege', severity: 'error',
      title: 'Wildcard tool grant',
      check: function (text, emit) {
        var fm = parseFrontmatter(text);
        if (fm && fm.data && /^\s*(\*|all)\s*$/i.test(String(fm.data.tools || ''))) {
          emit(1, 'tools: ' + fm.data.tools);
        }
      },
      message: 'Frontmatter grants a wildcard tool set — the skill may call anything.',
      fix: 'Allowlist only the tools the skill actually needs.' }
  ];

  var VAGUE_DESCRIPTIONS = [
    /^(a|an|the)?\s*(helpful|useful|simple|basic)?\s*(skill|tool|agent|assistant|utility)(\s+(for|that|to|which)\b.*)?\.?$/i,
    /^(does|do|helps?|handles?|provides?|offers?)\s+.{0,24}\.?$/i
  ];

  function parseFrontmatter(text) {
    var m = text.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
    if (!m) return null;
    var data = {};
    var malformed = [];
    var body = m[1].split(/\r?\n/);
    for (var i = 0; i < body.length; i++) {
      var ln = body[i];
      if (!ln.trim() || /^\s*#/.test(ln)) continue;
      var kv = ln.match(/^\s{0,3}([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
      if (kv) {
        data[kv[1]] = kv[2].trim().replace(/^["']|["']$/g, '');
      } else {
        malformed.push(i + 2); // +1 for 0-index, +1 for opening ---
      }
    }
    return { data: data, malformed: malformed };
  }

  function isVagueDescription(d) {
    var t = String(d).trim();
    if (t.length < 24) return true;
    for (var i = 0; i < VAGUE_DESCRIPTIONS.length; i++) {
      if (VAGUE_DESCRIPTIONS[i].test(t)) return true;
    }
    return false;
  }

  function gradeForScore(score) {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  function worseGrade(a, b) {
    return GRADE_ORDER[Math.max(GRADE_ORDER.indexOf(a), GRADE_ORDER.indexOf(b))];
  }

  // ---------------------------------------------------------------- scan
  function scan(text, opts) {
    opts = opts || {};
    var filename = opts.filename || 'SKILL.md';
    var isSkill = /SKILL\.md$/i.test(filename);
    var findings = [];
    var seen = {};

    function add(rule, line, matchText) {
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        line: line,
        match: excerpt(matchText == null ? '' : matchText),
        message: rule.message,
        fix: rule.fix
      });
    }

    RULES.forEach(function (rule) {
      function emit(line, matchText) {
        var key = rule.id + ':' + line;
        if (seen[key]) return;
        seen[key] = true;
        add(rule, line, matchText);
      }
      if (rule.patterns) {
        rule.patterns.forEach(function (re) {
          var flags = re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags;
          var rx = new RegExp(re.source, flags);
          var m;
          while ((m = rx.exec(text)) !== null) {
            emit(lineOf(text, m.index), m[0]);
            if (m[0].length === 0) rx.lastIndex++;
          }
        });
      }
      if (rule.check) rule.check(text, emit);
    });

    // ---- frontmatter lint ----
    var FM = {
      missing:  { id: 'Q-FM-001', category: 'frontmatter', severity: 'warning', title: 'Missing frontmatter block',
                  message: 'SKILL.md files are expected to carry a YAML frontmatter block (name, description).',
                  fix: 'Add ---\nname: <skill-name>\ndescription: <what it does>\n--- at the top.' },
      noname:   { id: 'Q-FM-002', category: 'frontmatter', severity: 'error', title: 'Missing name field',
                  message: 'Frontmatter has no `name` — agents cannot address or list the skill reliably.',
                  fix: 'Add `name: <kebab-case-name>` to the frontmatter.' },
      nodesc:   { id: 'Q-FM-003', category: 'frontmatter', severity: 'error', title: 'Missing description field',
                  message: 'Frontmatter has no `description` — the field agents use to decide when to invoke the skill.',
                  fix: 'Add a specific `description:` naming what the skill does and when to use it.' },
      vague:    { id: 'Q-FM-004', category: 'frontmatter', severity: 'warning', title: 'Vague description',
                  message: 'The description is too generic for an agent to route on (under 24 chars or boilerplate).',
                  fix: 'Write a concrete description: what it does, what input it takes, when to invoke it.' },
      badyml:   { id: 'Q-FM-005', category: 'frontmatter', severity: 'error', title: 'Malformed frontmatter',
                  message: 'Frontmatter contains lines that are not valid `key: value` pairs.',
                  fix: 'Fix the flagged lines — use `key: value`, two-space indentation, no tabs.' }
    };
    var fm = parseFrontmatter(text);
    if (!fm) {
      if (isSkill) add(FM.missing, 1, '(no --- block found)');
    } else {
      if (fm.malformed.length > 0) add(FM.badyml, fm.malformed[0], '(line ' + fm.malformed[0] + ' is not key: value)');
      if (!fm.data.name) add(FM.noname, 1, '(frontmatter)');
      if (!fm.data.description) add(FM.nodesc, 1, '(frontmatter)');
      else if (isVagueDescription(fm.data.description)) add(FM.vague, 1, fm.data.description);
    }

    // ---- structure ----
    if (!text.trim()) {
      add({ id: 'Q-ST-002', category: 'structure', severity: 'error', title: 'Empty file',
            message: 'The file has no content to scan.', fix: 'Provide the skill file content.' }, 1, '(empty)');
    } else {
      var lines = text.split(/\r?\n/);
      if (lines.length > 40 && !/^#{1,6}\s/m.test(text)) {
        add({ id: 'Q-ST-001', category: 'structure', severity: 'warning', title: 'No section headers',
              message: 'Long file with no Markdown headers — hard for agents and humans to navigate.',
              fix: 'Add ## section headers to structure the skill.' }, 1, '(document structure)');
      }
      for (var li = 0; li < lines.length; li++) {
        if (lines[li].length > 500) {
          add({ id: 'Q-ST-003', category: 'structure', severity: 'info', title: 'Very long line',
                message: 'A line exceeds 500 characters — usually a pasted blob that deserves a fence or file.',
                fix: 'Wrap or move the blob into a fenced block.' }, li + 1, lines[li]);
          break;
        }
      }
    }

    // ---- score ----
    var score = 100;
    var criticals = 0;
    var summary = { critical: 0, error: 0, warning: 0, info: 0 };
    findings.forEach(function (f) {
      score -= (DEDUCTIONS[f.severity] || 0);
      summary[f.severity]++;
      if (f.severity === 'critical') criticals++;
    });
    if (score < 0) score = 0;
    var grade = gradeForScore(score);
    if (criticals > 0) grade = worseGrade(grade, 'D'); // any critical caps the grade at D

    findings.sort(function (a, b) {
      var d = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      return d !== 0 ? d : a.line - b.line;
    });

    return {
      engine: 'cwi-skill-sentinel',
      engine_version: VERSION,
      filename: filename,
      scanned_at: new Date().toISOString(),
      score: score,
      grade: grade,
      summary: summary,
      findings: findings
    };
  }

  return {
    VERSION: VERSION,
    RULES: RULES.map(function (r) { return { id: r.id, category: r.category, severity: r.severity, title: r.title }; }),
    scan: scan,
    gradeForScore: gradeForScore,
    parseFrontmatter: parseFrontmatter
  };
});
