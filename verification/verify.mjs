import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';

const repoRoot = path.resolve(import.meta.dirname, '..');
const artifactRoot = path.join(repoRoot, 'artifacts');
const evidenceRoot = path.join(repoRoot, 'verification', 'evidence');
const attachments = ['输入数据包.zip', 'reference.zip', '关键标准答案.xlsx', '任务规格转化.xlsx'];
const expectedOutputs = [
  'output/reports/dependency_inventory.csv',
  'output/reports/license_findings.csv',
  'output/reports/release_decision.json',
  'output/reports/vulnerability_gate.csv',
  'output/src/audit_release_deps.mjs',
].sort();
const reportKeys = {
  'output/reports/dependency_inventory.csv': ['path'],
  'output/reports/license_findings.csv': ['package_name', 'version'],
  'output/reports/vulnerability_gate.csv': ['package_name', 'advisory_id'],
};
const assert = (value, message) => { if (!value) throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sha256File = (file) => sha256(fs.readFileSync(file));

function zipEntries(file) {
  const data = fs.readFileSync(file);
  let eocd = -1;
  for (let index = data.length - 22; index >= Math.max(0, data.length - 65_557); index -= 1) {
    if (data.readUInt32LE(index) === 0x06054b50) { eocd = index; break; }
  }
  assert(eocd >= 0, `找不到ZIP目录：${file}`);
  const count = data.readUInt16LE(eocd + 10);
  let offset = data.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let entryIndex = 0; entryIndex < count; entryIndex += 1) {
    assert(data.readUInt32LE(offset) === 0x02014b50, `ZIP目录损坏：${file}`);
    const method = data.readUInt16LE(offset + 10);
    const compressedSize = data.readUInt32LE(offset + 20);
    const uncompressedSize = data.readUInt32LE(offset + 24);
    const nameLength = data.readUInt16LE(offset + 28);
    const extraLength = data.readUInt16LE(offset + 30);
    const commentLength = data.readUInt16LE(offset + 32);
    const localOffset = data.readUInt32LE(offset + 42);
    const name = data.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').replaceAll('\\', '/');
    const localNameLength = data.readUInt16LE(localOffset + 26);
    const localExtraLength = data.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + localExtraLength;
    if (!name.endsWith('/')) {
      const compressed = data.subarray(start, start + compressedSize);
      const body = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : null;
      assert(body && body.length === uncompressedSize, `无法解压${name}`);
      entries.set(name, body);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

async function extract(file, destination) {
  for (const [name, bytes] of zipEntries(file)) {
    const target = path.resolve(destination, ...name.split('/'));
    assert(target.startsWith(`${path.resolve(destination)}${path.sep}`), `非法ZIP路径：${name}`);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, bytes);
  }
}

function workbookSheets(file) {
  const xml = zipEntries(file).get('xl/workbook.xml')?.toString('utf8') ?? '';
  return [...xml.matchAll(/<(?:[A-Za-z]+:)?sheet[^>]+name="([^"]+)"/gu)].map((match) => match[1]);
}

async function run(command, args, cwd) {
  const started = Date.now();
  return await new Promise((resolve) => {
    let child;
    try { child = spawn(command, args, { cwd, env: process.env, windowsHide: true }); }
    catch (error) { resolve({ code: 1, stdout: '', stderr: error.stack ?? error.message, elapsed_ms: Date.now() - started }); return; }
    let stdout = '';
    let stderr = '';
    let settled = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => {
      if (!settled) { settled = true; resolve({ code: 1, stdout, stderr: `${stderr}${error.stack ?? error.message}`, elapsed_ms: Date.now() - started }); }
    });
    child.on('exit', (code) => {
      if (!settled) { settled = true; resolve({ code: code ?? 1, stdout, stderr, elapsed_ms: Date.now() - started }); }
    });
  });
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { cell += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(cell); cell = ''; }
    else if (char === '\n') { row.push(cell.replace(/\r$/u, '')); rows.push(row); row = []; cell = ''; }
    else cell += char;
  }
  if (cell || row.length) { row.push(cell.replace(/\r$/u, '')); rows.push(row); }
  const headers = rows.shift() ?? [];
  return rows.filter((values) => values.some((value) => value !== '')).map((values) =>
    Object.fromEntries(headers.map((header, index) => [header, values[index] ?? '']))
  );
}

function normalizeCsv(file, text) {
  const keys = reportKeys[file];
  return parseCsv(text).toSorted((left, right) =>
    keys.map((key) => String(left[key]).localeCompare(String(right[key]), 'en')).find((value) => value !== 0) ?? 0
  );
}

function normalizeDecision(value) {
  return {
    ...value,
    blockers: [...value.blockers].toSorted((left, right) => `${left.package_name}|${left.advisory_id}`.localeCompare(`${right.package_name}|${right.advisory_id}`, 'en')),
    warnings: [...value.warnings].toSorted((left, right) => left.package_name.localeCompare(right.package_name, 'en')),
  };
}

function files(root) {
  const result = [];
  function walk(current, prefix = '') {
    if (!fs.existsSync(current)) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path.join(current, entry.name), relative);
      else result.push(relative);
    }
  }
  walk(root);
  return result.sort();
}

function treeDigest(root, ignored = new Set()) {
  const lines = [];
  function walk(current, prefix = '') {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).toSorted((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (ignored.has(relative.split('/')[0])) continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full, relative);
      else lines.push(`${relative}\0${sha256File(full)}`);
    }
  }
  walk(root);
  return sha256(Buffer.from(lines.join('\n')));
}

function classifyExecutable(name, bytes) {
  const lower = name.toLowerCase();
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1, 4).toString('ascii') === 'ELF') return 'linux_elf';
  if (/\.(?:sh|bash|so)(?:\.|$)/u.test(lower)) return 'posix_member';
  if (/^#!.*(?:ba|z|k)?sh/mu.test(bytes.subarray(0, 160).toString('utf8'))) return 'posix_shebang';
  return null;
}

async function prepare(label, mutate) {
  const root = path.join(os.tmpdir(), label);
  await fsp.rm(root, { recursive: true, force: true });
  await fsp.mkdir(root, { recursive: true });
  await extract(path.join(artifactRoot, '输入数据包.zip'), root);
  const inputRoot = path.join(root, 'input_data');
  const standard = zipEntries(path.join(artifactRoot, 'reference.zip'));
  const outputRoot = path.join(inputRoot, 'output');
  await fsp.mkdir(path.join(outputRoot, 'src'), { recursive: true });
  await fsp.writeFile(path.join(outputRoot, 'src', 'audit_release_deps.mjs'), standard.get('output/src/audit_release_deps.mjs'));
  if (mutate) await mutate(inputRoot);
  return { inputRoot, outputRoot, standard };
}

async function execute(room) {
  return await run(process.execPath, [path.join(room.inputRoot, 'tools', 'run_task.mjs')], room.inputRoot);
}

function compareStandard(room) {
  const actualPaths = files(room.outputRoot).map((name) => `output/${name}`);
  assert(JSON.stringify(actualPaths) === JSON.stringify(expectedOutputs), `输出成员不一致：${actualPaths.join(',')}`);
  const sourceActual = fs.readFileSync(path.join(room.outputRoot, 'src', 'audit_release_deps.mjs'), 'utf8').replaceAll('\r\n', '\n');
  const sourceExpected = room.standard.get('output/src/audit_release_deps.mjs').toString('utf8').replaceAll('\r\n', '\n');
  assert(sourceActual === sourceExpected, '完成版程序与标准交付不一致');
  const normalized = {};
  for (const file of Object.keys(reportKeys)) {
    const actual = normalizeCsv(file, fs.readFileSync(path.join(room.inputRoot, ...file.split('/')), 'utf8'));
    const expected = normalizeCsv(file, room.standard.get(file).toString('utf8'));
    assert(JSON.stringify(actual) === JSON.stringify(expected), `${file}业务字段不一致`);
    normalized[file] = actual;
  }
  const decisionFile = 'output/reports/release_decision.json';
  const actualDecision = normalizeDecision(JSON.parse(fs.readFileSync(path.join(room.inputRoot, ...decisionFile.split('/')), 'utf8')));
  const expectedDecision = normalizeDecision(JSON.parse(room.standard.get(decisionFile).toString('utf8')));
  assert(JSON.stringify(actualDecision) === JSON.stringify(expectedDecision), '发布裁决业务字段不一致');
  normalized[decisionFile] = actualDecision;
  return sha256(Buffer.from(JSON.stringify(normalized)));
}

await fsp.rm(evidenceRoot, { recursive: true, force: true });
await fsp.mkdir(evidenceRoot, { recursive: true });
assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', '只接受GitHub托管Windows运行');
assert(/^v24\./u.test(process.version), `需要Node.js24，当前为${process.version}`);

const attachmentSha256 = Object.fromEntries(attachments.map((name) => [name, sha256File(path.join(artifactRoot, name))]));
const inputMembers = zipEntries(path.join(artifactRoot, '输入数据包.zip'));
const standardMembers = [...zipEntries(path.join(artifactRoot, 'reference.zip')).keys()].sort();
const executableScan = [...inputMembers].map(([name, bytes]) => ({ name, classification: classifyExecutable(name, bytes) })).filter((item) => item.classification);
assert(executableScan.length === 0, `输入包含平台专用成员：${JSON.stringify(executableScan)}`);
assert(JSON.stringify(standardMembers) === JSON.stringify(expectedOutputs), '标准交付成员错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx'))) === JSON.stringify(['交付物答案清单', '固定字段答案', '固定集合答案', '固定数值答案', '允许变体答案']), '关键标准答案Sheet错误');
assert(JSON.stringify(workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx'))) === JSON.stringify(['任务规格转化']), '任务规格Sheet错误');

const completedProgram = zipEntries(path.join(artifactRoot, 'reference.zip')).get('output/src/audit_release_deps.mjs').toString('utf8');
assert(!/\b(?:express|lodash|left-pad|qs|xml2js|event-stream|gpl-helper|GHSA-qs-2026-001|CVE-2023-0842|MAL-2018-001)\b/u.test(completedProgram), '完成版程序含样例依赖或漏洞主键硬编码');
const staticReview = JSON.parse(fs.readFileSync(path.join(repoRoot, 'qa', 'static-review.json'), 'utf8'));
const scoreAnswerLeak = JSON.parse(fs.readFileSync(path.join(repoRoot, 'qa', 'score-answer-leak.json'), 'utf8'));
const candidateScore = fs.readFileSync(path.join(repoRoot, 'task', '评分表.txt'), 'utf8');
const scoreLeakPatterns = [
  /\b(?:express|lodash|left-pad|qs|xml2js|event-stream|gpl-helper|@search\/ui-kit|@vendor\/report-exporter)\b/gu,
  /\b(?:GHSA-[A-Za-z0-9-]+|CVE-\d{4}-\d+|MAL-\d{4}-\d+|EX-[A-Za-z0-9-]+)\b/gu,
  /(?:完整|全部)(?:通过|拒绝|放行|阻断|结果)(?:集合|清单)/gu,
  /(?:固定|共计|总计|恰好|正好|分别有)\s*\d+\s*(?:行|条|组|个|份|项)/gu,
  /(?:依次|分别)为[^。\n]+/gu,
];
const currentScoreLeakHits = scoreLeakPatterns.flatMap((pattern) => [...candidateScore.matchAll(pattern)].map((match) => match[0]));
assert(staticReview.result === 'PASS' && staticReview.task_spec_column_count === 2 && staticReview.humanizer_score >= 45, '静态审计、任务规格或语言分不合格');
assert(scoreAnswerLeak.pass === true && scoreAnswerLeak.hit_count === 0 && currentScoreLeakHits.length === 0, `候选人评分表泄露样本答案：${JSON.stringify(currentScoreLeakHits)}`);

const cleanRuns = [];
for (const label of ['Q10419 第一处 中文 空格目录', 'Q10419 第二处 中文 路径']) {
  const room = await prepare(label);
  const before = treeDigest(room.inputRoot, new Set(['output']));
  const execution = await execute(room);
  assert(execution.code === 0, `${label}处理失败\n${execution.stdout}\n${execution.stderr}`);
  const after = treeDigest(room.inputRoot, new Set(['output']));
  assert(before === after, `${label}修改了业务输入`);
  const semanticDigest = compareStandard(room);
  cleanRuns.push({ directory_label: label, exit_code: execution.code, elapsed_ms: execution.elapsed_ms, input_digest_before: before, input_digest_after: after, semantic_digest: semanticDigest, standard_match: true });
}
assert(cleanRuns[0].semantic_digest === cleanRuns[1].semantic_digest, '两个目录的结构化结果不一致');

const crlf = await prepare('Q10419 CRLF owner映射', async (inputRoot) => {
  const file = path.join(inputRoot, 'owners.csv');
  await fsp.writeFile(file, (await fsp.readFile(file, 'utf8')).replace(/\r?\n/gu, '\r\n'));
});
let execution = await execute(crlf);
assert(execution.code === 0, `CRLF输入处理失败\n${execution.stdout}\n${execution.stderr}`);
const crlfDigest = compareStandard(crlf);
assert(crlfDigest === cleanRuns[0].semantic_digest, 'CRLF输入改变业务结果');

const mutation = await prepare('Q10419 策略日期变化', async (inputRoot) => {
  const file = path.join(inputRoot, 'rules', 'license_policy.json');
  const policy = JSON.parse(await fsp.readFile(file, 'utf8'));
  policy.report_date = '2026-09-15';
  await fsp.writeFile(file, `${JSON.stringify(policy, null, 2)}\n`);
});
execution = await execute(mutation);
assert(execution.code === 0, `策略日期变化后处理失败\n${execution.stdout}\n${execution.stderr}`);
const mutationVulnerabilities = parseCsv(await fsp.readFile(path.join(mutation.outputRoot, 'reports', 'vulnerability_gate.csv'), 'utf8'));
const changedAdvisory = mutationVulnerabilities.find((row) => row.advisory_id === 'GHSA-qs-2026-001');
assert(changedAdvisory?.exception_status === 'expired' && changedAdvisory?.gate_action === 'block', `策略日期未联动例外处置：${JSON.stringify(changedAdvisory)}`);
const mutationDecision = JSON.parse(await fsp.readFile(path.join(mutation.outputRoot, 'reports', 'release_decision.json'), 'utf8'));
assert(mutationDecision.blockers.some((row) => row.package_name === 'qs') && !mutationDecision.warnings.some((row) => row.package_name === 'qs'), '策略日期未联动发布裁决');

const invalid = await prepare('Q10419 无效owner输入', async (inputRoot) => { await fsp.rm(path.join(inputRoot, 'owners.csv')); });
execution = await execute(invalid);
const invalidReportsAbsent = !fs.existsSync(path.join(invalid.outputRoot, 'reports'));
const invalidSolutionPreserved = fs.existsSync(path.join(invalid.outputRoot, 'src', 'audit_release_deps.mjs'));
assert(execution.code !== 0 && invalidReportsAbsent && invalidSolutionPreserved, '无效输入没有中止处理或污染交付程序');

const evidence = {
  schema_version: 1,
  task_asset_id: 'node_dependency_release_disposition',
  result: 'PASS',
  generated_at_utc: new Date().toISOString(),
  git_commit_sha: process.env.GITHUB_SHA,
  workflow_run_id: process.env.GITHUB_RUN_ID,
  runner: { os: process.env.RUNNER_OS, arch: process.env.RUNNER_ARCH, image_os: process.env.ImageOS, image_version: process.env.ImageVersion, node: process.version, actual_windows_run: true, powershell_hosted_workflow: true },
  software: { node: process.version, entry: 'node tools/run_task.mjs' },
  attachment_sha256: attachmentSha256,
  archive_checks: { input_members: [...inputMembers.keys()].sort(), standard_output_members: standardMembers, prohibited_platform_members: executableScan },
  workbook_checks: { answer_sheet_names: workbookSheets(path.join(artifactRoot, '关键标准答案.xlsx')), specification_sheet_names: workbookSheets(path.join(artifactRoot, '任务规格转化.xlsx')), task_spec_column_count: staticReview.task_spec_column_count, candidate_score_answer_leak_hits: currentScoreLeakHits.length },
  clean_runs: cleanRuns,
  crlf_case: { changed_input: 'owners.csv行尾改为CRLF', exit_code: 0, semantic_digest: crlfDigest, standard_match: true },
  positive_business_change: { changed_rule: 'report_date改为2026-09-15', exit_code: 0, changed_advisory: changedAdvisory, decision_result: mutationDecision.result },
  invalid_input: { removed_input: 'owners.csv', exit_code: execution.code, reports_absent: invalidReportsAbsent, solution_preserved: invalidSolutionPreserved },
  network: { formal_run_access: 'none' },
};
await fsp.writeFile(path.join(evidenceRoot, 'windows-verification.json'), `${JSON.stringify(evidence, null, 2)}\n`);
await fsp.writeFile(path.join(evidenceRoot, 'windows-audit.json'), `${JSON.stringify({ schema_version: 1, task_asset_id: evidence.task_asset_id, result: evidence.result, platform: process.platform, node_version: process.version, attachment_sha256: attachmentSha256, clean_directory_count: cleanRuns.length, crlf_pass: true, positive_business_change_pass: true, invalid_input_pass: true }, null, 2)}\n`);
console.log(JSON.stringify(evidence, null, 2));
