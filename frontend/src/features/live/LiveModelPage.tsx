import { FormEvent, useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Download, FileArchive, FileCode2, Play, RefreshCw, Settings, ShieldCheck } from 'lucide-react';

import { runLiveModel } from '../../api/demo';
import type {
  ArtifactValidationResult,
  LiveModelLaneResult,
  LiveModelRunRequest,
  LiveModelRunResponse,
  LiveModelSandboxCheck,
  LiveModelSandboxSummary,
  LiveModelStep,
} from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { StatusPill } from '../../components/StatusPill';
import {
  koreanCacheLabel,
  koreanReasonCodeTitle,
  koreanRouteKindLabel,
  koreanStatusLabel,
} from '../../lib/koreanLabels';

const defaultRequest: LiveModelRunRequest = {
  repo_id: 'hf-internal-testing/tiny-random-bert',
  revision: 'main',
  skip_weights: false,
  enable_path_b: false,
  include_patterns: [],
  exclude_patterns: [],
  requested_by: 'demo_presenter',
};

const plannedSteps = [
  'Hugging Face 모델 다운로드',
  '파일 분류',
  '가중치 검사',
  'Python 코드 검사',
  'config 검사',
  '샌드박스 실행 근거',
  '최종 릴리스 판정',
];

function splitPatterns(value: string) {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function statusTone(value: unknown): 'ok' | 'warn' | 'bad' | 'info' {
  const text = String(value ?? '').toUpperCase();
  if (['PASS', 'APPROVE', 'APPROVE_WITH_TRANSFORM'].includes(text)) return 'ok';
  if (['BLOCK', 'DENY', 'ERROR'].includes(text)) return 'bad';
  if (['PENDING_REVIEW', 'REVIEW_REQUIRED', 'SKIPPED'].includes(text)) return 'warn';
  return 'info';
}

function laneIcon(lane: string) {
  if (lane === 'weights') return FileArchive;
  if (lane === 'python') return FileCode2;
  return Settings;
}

function firstReason(result: ArtifactValidationResult) {
  return result.reason_entries[0]?.code ?? '사유 없음';
}

function firstReasonLabel(result: ArtifactValidationResult) {
  const code = firstReason(result);
  return code === '사유 없음' ? code : koreanReasonCodeTitle(code);
}

function durationLabel(step: LiveModelStep) {
  if (step.duration_ms === null || step.duration_ms === undefined) return '';
  if (step.duration_ms < 1000) return `${step.duration_ms}ms`;
  return `${(step.duration_ms / 1000).toFixed(1)}초`;
}

function fileKindLabel(kind: string) {
  if (kind === 'SAFETENSORS' || kind === 'PICKLE') return '가중치';
  if (kind === 'PYTHON') return 'Python';
  if (kind.includes('CONFIG') || kind.includes('JSON') || kind.includes('TOKEN')) return 'config';
  return kind;
}

function explainFinal(result: LiveModelRunResponse) {
  const decision = result.validation_response.overall_decision;
  if (decision === 'APPROVE') return '모든 검증 대상이 통과해 릴리스 승인 흐름으로 갈 수 있습니다.';
  if (decision === 'APPROVE_WITH_TRANSFORM') return '원본 그대로가 아니라 안전한 산출물로 변환한 뒤 승인하는 흐름입니다.';
  if (decision === 'DENY') return '차단 조건이 발견되어 이 모델은 릴리스하면 안 됩니다.';
  if (decision === 'REVIEW_REQUIRED') return '자동 승인하기에는 근거가 부족해 보안 담당자 검토가 필요합니다.';
  return '오류가 있어 검증 결과를 확정할 수 없습니다.';
}

function textValue(value: unknown, fallback = '없음') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function booleanValue(value: unknown) {
  if (value === true) return '예';
  if (value === false) return '아니오';
  return '미확인';
}

function eventCount(value: unknown) {
  return Array.isArray(value) ? value.length : 0;
}

function totalSecurityEvents(check: LiveModelSandboxCheck) {
  return Object.values(check.security_events).reduce<number>((total, value) => total + eventCount(value), 0);
}

function sandboxDecisionLabel(decision: string) {
  const labels: Record<string, string> = {
    NOT_RUN: '실행 안 됨 (NOT_RUN)',
    SANDBOX_INFRA_ERROR: '샌드박스 준비 오류',
    BLOCKED_RUNTIME_INVALID: '격리 설정 위반 차단',
    BLOCKED_SECURITY_EVENT: '보안 이벤트 차단',
    FUNCTIONAL_REVIEW_REQUIRED: '기능 검토 필요',
    FORWARD_SKIPPED_REVIEW: 'forward 미실행 검토',
    HIGH_RISK_REVIEW: '고위험 검토',
    B2_SANDBOX_OBSERVED_CLEAN: '샌드박스 관찰상 이상 없음',
    B2_POLICY_REVIEW_REQUIRED: 'B-2 정책 검토 필요',
    LOG_INCOMPLETE: '로그 불완전',
    ERROR: '오류',
  };
  return labels[decision] ?? decision;
}

function sandboxExecutionText(check: LiveModelSandboxCheck) {
  return [
    `import ${textValue(check.execution.import_status)}`,
    `instantiate ${textValue(check.execution.instantiate_status)}`,
    `forward ${textValue(check.execution.forward_status)}`,
  ].join(' / ');
}

function sandboxIsolationText(check: LiveModelSandboxCheck) {
  return [
    `runtime ${textValue(check.runtime_evidence.runtime ?? check.sandbox_runtime)}`,
    `network ${textValue(check.runtime_evidence.network_mode)}`,
    `read-only ${booleanValue(check.runtime_evidence.rootfs_readonly)}`,
  ].join(' / ');
}

function sandboxSecurityText(check: LiveModelSandboxCheck) {
  const parts = [
    ['네트워크', check.security_events.network_events],
    ['execve', check.security_events.unexpected_execve],
    ['쓰기 차단', check.security_events.blocked_writes],
    ['비밀 경로', check.security_events.secret_path_access],
    ['읽기 차단', check.security_events.blocked_reads],
  ]
    .map(([label, value]) => `${label} ${eventCount(value)}건`);
  return parts.join(' / ');
}

function shortHash(value: unknown) {
  const text = textValue(value);
  if (text === '없음' || text.length <= 16) return text;
  return `${text.slice(0, 16)}...`;
}

function PlannedProgress({ running }: { running: boolean }) {
  return (
    <div className="live-progress-list" aria-label="실행 예정 단계">
      {plannedSteps.map((title, index) => (
        <div key={title}>
          <StatusPill tone={running && index === 0 ? 'info' : 'warn'}>
            {running && index === 0 ? '진행 중' : '대기'}
          </StatusPill>
          <strong>{title}</strong>
          <span>{index === 0 ? '모델 repo snapshot을 준비합니다.' : '앞 단계가 끝나면 순서대로 표시됩니다.'}</span>
        </div>
      ))}
    </div>
  );
}

function CompletedProgress({ steps }: { steps: LiveModelStep[] }) {
  return (
    <div className="live-progress-list" aria-label="완료된 진행 단계">
      {steps.map((step) => (
        <div key={`${step.id}-${step.title}`}>
          <StatusPill tone={statusTone(step.status)}>{koreanStatusLabel(step.status)}</StatusPill>
          <strong>{step.title}</strong>
          <span>{step.detail}</span>
          {durationLabel(step) ? <small>{durationLabel(step)}</small> : null}
          {step.items.length ? (
            <ul>
              {step.items.slice(0, 5).map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function LanePanel({ lane }: { lane: LiveModelLaneResult }) {
  const Icon = laneIcon(lane.lane);
  return (
    <section className="section-block live-lane-panel" aria-label={`${lane.title} 결과`}>
      <div className="section-title-row">
        <div className="lane-heading">
          <Icon aria-hidden="true" size={20} />
          <div>
            <h2>{lane.title}</h2>
            <p className="quiet-copy">{lane.description}</p>
          </div>
        </div>
        <StatusPill tone={statusTone(lane.status)}>{koreanStatusLabel(lane.status)}</StatusPill>
      </div>
      {lane.results.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>파일</th>
                <th>상태</th>
                <th>등급</th>
                <th>검사 경로</th>
                <th>사유</th>
                <th>캐시</th>
              </tr>
            </thead>
            <tbody>
              {lane.results.map((result) => (
                <tr key={`${lane.lane}-${result.artifact.artifact_id}-${result.route_kind}`}>
                  <td>
                    <strong>{result.artifact.repo_path}</strong>
                    <small>{fileKindLabel(result.artifact.file_kind)}</small>
                  </td>
                  <td><StatusPill tone={statusTone(result.status)}>{koreanStatusLabel(result.status)}</StatusPill></td>
                  <td>{result.grade}</td>
                  <td>{koreanRouteKindLabel(result.route_kind)}</td>
                  <td>
                    <strong>{firstReasonLabel(result)}</strong>
                    <small>{firstReason(result)}</small>
                  </td>
                  <td>{koreanCacheLabel(result.cache_hit)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="quiet-copy">이 종류의 검증 대상 파일이 없습니다.</p>
      )}
    </section>
  );
}

function SandboxPanel({ summary }: { summary: LiveModelSandboxSummary }) {
  return (
    <section className="section-block live-sandbox-panel" aria-labelledby="sandbox-title">
      <div className="section-title-row">
        <div>
          <h2 id="sandbox-title">샌드박스 실행 근거</h2>
          <p className="quiet-copy">{summary.message}</p>
        </div>
        <StatusPill tone={statusTone(summary.status)}>{koreanStatusLabel(summary.status)}</StatusPill>
      </div>

      <div className="sandbox-summary-grid">
        <div>
          <span>Path B 요청</span>
          <strong>{summary.requested ? '요청함' : '요청 안 함'}</strong>
        </div>
        <div>
          <span>B-2 샌드박스 대상</span>
          <strong>{summary.eligible_count}</strong>
        </div>
        <div>
          <span>근거 수집</span>
          <strong>{summary.check_count}</strong>
        </div>
        <div>
          <span>실제 실행 흔적</span>
          <strong>{summary.ran_count}</strong>
        </div>
        <div>
          <span>보안 이벤트</span>
          <strong>{summary.blocked_event_count}</strong>
        </div>
      </div>

      {summary.checks.length ? (
        <div className="sandbox-check-list">
          {summary.checks.map((check) => (
            <div key={`${check.artifact_id}-${check.repo_path}`}>
              <div className="sandbox-check-heading">
                <div>
                  <strong>{check.repo_path}</strong>
                  <span>{check.grade} / {check.route_kind}</span>
                </div>
                <StatusPill tone={statusTone(check.status)}>{sandboxDecisionLabel(check.decision)}</StatusPill>
              </div>
              <dl>
                <div>
                  <dt>정책 게이트</dt>
                  <dd>
                    <strong>{koreanReasonCodeTitle(check.reason_code)}</strong>
                    <small>{textValue(check.reason_code)}</small>
                  </dd>
                </div>
                <div>
                  <dt>실행 단계</dt>
                  <dd>{sandboxExecutionText(check)}</dd>
                </div>
                <div>
                  <dt>격리 설정</dt>
                  <dd>{sandboxIsolationText(check)}</dd>
                </div>
                <div>
                  <dt>보안 이벤트</dt>
                  <dd>{sandboxSecurityText(check)}</dd>
                </div>
                <div>
                  <dt>manifest</dt>
                  <dd>{shortHash(check.manifest_evidence.host_manifest_sha256)}</dd>
                </div>
                <div>
                  <dt>릴리스 가능</dt>
                  <dd>{check.deployable ? '가능' : '불가'}</dd>
                </div>
              </dl>
              {totalSecurityEvents(check) > 0 ? (
                <p className="quiet-copy">보안 이벤트가 있어 자동 승인으로 처리하지 않습니다.</p>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <div className="live-explain-box">
          <ShieldCheck aria-hidden="true" size={18} />
          <span>B-2로 분류된 Python 코드가 있고 Path B가 켜져 있을 때 이 영역에 gVisor/runsc 실행 근거가 표시됩니다.</span>
        </div>
      )}
    </section>
  );
}

export function LiveModelPage() {
  const [repoId, setRepoId] = useState(defaultRequest.repo_id);
  const [revision, setRevision] = useState(defaultRequest.revision);
  const [skipWeights, setSkipWeights] = useState(defaultRequest.skip_weights);
  const [enablePathB, setEnablePathB] = useState(defaultRequest.enable_path_b);
  const [includeText, setIncludeText] = useState('');
  const [excludeText, setExcludeText] = useState('');

  const includePatterns = useMemo(() => splitPatterns(includeText), [includeText]);
  const excludePatterns = useMemo(() => splitPatterns(excludeText), [excludeText]);

  const mutation = useMutation({
    mutationFn: () => runLiveModel({
      repo_id: repoId.trim(),
      revision: revision.trim() || 'main',
      skip_weights: skipWeights,
      enable_path_b: enablePathB,
      include_patterns: includePatterns,
      exclude_patterns: excludePatterns,
      requested_by: 'demo_presenter',
    }),
  });

  const result = mutation.data;
  const finalDecision = result?.validation_response.overall_decision;

  return (
    <section className="console-panel live-model-panel" aria-labelledby="live-model-title">
      <div className="section-kicker">실제 모델</div>
      <div className="overview-heading">
        <div>
          <h1 id="live-model-title">실제 Hugging Face 모델 실행</h1>
          <p>모델 ID를 입력하면 다운로드, 파일 분류, 가중치/Python/config 검사, 최종 판정까지 한 화면에서 순서대로 보여줍니다.</p>
        </div>
        <StatusPill tone={result ? statusTone(result.validation_response.overall_status) : mutation.isPending ? 'info' : 'warn'}>
          {result ? koreanStatusLabel(result.validation_response.overall_status) : mutation.isPending ? '실행 중' : '대기'}
        </StatusPill>
      </div>

      <section className="section-block live-runner" aria-labelledby="live-runner-title">
        <div className="section-title-row">
          <div>
            <h2 id="live-runner-title">모델 입력</h2>
            <p className="quiet-copy">처음에는 작은 공개 모델로 시연하는 것이 안전합니다. 큰 가중치 포함은 시간이 오래 걸릴 수 있습니다.</p>
          </div>
          <StatusPill tone={skipWeights ? 'info' : 'warn'}>
            {skipWeights ? '빠른 시연' : '가중치 포함'}
          </StatusPill>
        </div>
        <form
          className="ops-form"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="live-form-grid">
            <label className="field-stack">
              <span>Hugging Face 모델 ID</span>
              <input value={repoId} onChange={(event) => setRepoId(event.currentTarget.value)} placeholder="owner/model" />
            </label>
            <label className="field-stack">
              <span>Revision</span>
              <input value={revision} onChange={(event) => setRevision(event.currentTarget.value)} placeholder="main" />
            </label>
          </div>
          <div className="run-actions live-options">
            <label>
              <input type="checkbox" checked={skipWeights} onChange={(event) => setSkipWeights(event.currentTarget.checked)} />
              <span>큰 가중치는 제외하고 빠르게 보기</span>
            </label>
            <label>
              <input type="checkbox" checked={enablePathB} onChange={(event) => setEnablePathB(event.currentTarget.checked)} />
              <span>Path B/gVisor 근거 요청</span>
            </label>
            <button type="submit" className="primary-link" disabled={mutation.isPending || !repoId.trim()}>
              {mutation.isPending ? <RefreshCw aria-hidden="true" size={16} /> : <Play aria-hidden="true" size={16} />}
              <span>{mutation.isPending ? '실행 중' : '실제 모델 실행'}</span>
            </button>
          </div>
          <div className="live-form-grid">
            <label className="field-stack">
              <span>포함할 파일 패턴</span>
              <textarea value={includeText} onChange={(event) => setIncludeText(event.currentTarget.value)} placeholder="비워두면 기본 패턴 사용&#10;예: config.json, *.py" />
            </label>
            <label className="field-stack">
              <span>제외할 파일 패턴</span>
              <textarea value={excludeText} onChange={(event) => setExcludeText(event.currentTarget.value)} placeholder="예: *.bin, pytorch_model-*.bin" />
            </label>
          </div>
        </form>
        {mutation.error ? <ErrorPanel title="실제 모델 실행 실패" message={mutation.error instanceof Error ? mutation.error.message : String(mutation.error)} /> : null}
      </section>

      <section className="section-block" aria-labelledby="progress-title">
        <div className="section-title-row">
          <div>
            <h2 id="progress-title">진행 과정</h2>
            <p className="quiet-copy">각 줄은 실제 모델이 시스템 안에서 지나간 단계를 뜻합니다.</p>
          </div>
          <Download aria-hidden="true" size={20} />
        </div>
        {result ? <CompletedProgress steps={result.steps} /> : <PlannedProgress running={mutation.isPending} />}
      </section>

      {result ? (
        <>
          <section className="section-block live-final" aria-labelledby="live-final-title">
            <div className="section-title-row">
              <div>
                <h2 id="live-final-title">최종 판정 읽는 법</h2>
                <p className="quiet-copy">{explainFinal(result)}</p>
              </div>
              <StatusPill tone={statusTone(finalDecision)}>{koreanStatusLabel(finalDecision)}</StatusPill>
            </div>
            <div className="run-summary-grid">
              <div>
                <span>모델</span>
                <strong>{result.repo_id}</strong>
              </div>
              <div>
                <span>작업 판정</span>
                <strong>{koreanStatusLabel(result.validation_response.overall_decision)}</strong>
              </div>
              <div>
                <span>산출물 상태</span>
                <strong>{koreanStatusLabel(result.validation_response.overall_status)}</strong>
              </div>
              <div>
                <span>릴리스 조치</span>
                <strong>{result.validation_response.release_action}</strong>
              </div>
            </div>
            <div className="live-explain-box">
              <ShieldCheck aria-hidden="true" size={18} />
              <span>A/B-1/B-2/C는 Python 코드 등급이고, PASS/BLOCK/PENDING_REVIEW는 artifact 상태입니다. 최종 APPROVE/DENY/REVIEW_REQUIRED는 모든 파일 결과를 합친 job decision입니다.</span>
            </div>
          </section>

          <div className="metric-grid metric-grid-four">
            <div className="metric-tile">
              <span>검증 대상</span>
              <strong>{result.file_summary.total_supported ?? result.artifacts.length}</strong>
              <small>지원되는 파일 종류</small>
            </div>
            <div className="metric-tile">
              <span>가중치</span>
              <strong>{result.file_summary.weights ?? 0}</strong>
              <small>{result.fast_mode ? `${result.file_summary.skipped_weights_fast_mode ?? 0}개 빠른 시연 제외` : '포함 실행'}</small>
            </div>
            <div className="metric-tile">
              <span>Python</span>
              <strong>{result.file_summary.python ?? 0}</strong>
              <small>A/B-1/B-2/C 등급 대상</small>
            </div>
            <div className="metric-tile">
              <span>config</span>
              <strong>{result.file_summary.config ?? 0}</strong>
              <small>schema와 auto_map 확인</small>
            </div>
          </div>

          <div className="live-lane-grid">
            {result.lane_results.map((lane) => <LanePanel key={lane.lane} lane={lane} />)}
          </div>

          <SandboxPanel summary={result.sandbox_summary} />

          <section className="section-block" aria-labelledby="skipped-title">
            <h2 id="skipped-title">제외되거나 분류되지 않은 파일</h2>
            <div className="skipped-grid">
              {Object.entries(result.skipped).map(([key, paths]) => (
                <div key={key}>
                  <strong>{key}</strong>
                  {paths.length ? (
                    <ul>
                      {paths.slice(0, 12).map((path) => <li key={`${key}-${path}`}>{path}</li>)}
                    </ul>
                  ) : (
                    <span>없음</span>
                  )}
                </div>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </section>
  );
}
