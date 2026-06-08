import {
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  FileArchive,
  FileCode2,
  GitBranch,
  PackageSearch,
  Play,
  Settings,
  ShieldCheck,
  UploadCloud,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

import { fetchOverviewData } from '../../api/overview';
import { ErrorPanel } from '../../components/ErrorPanel';
import { MetricTile } from '../../components/MetricTile';
import { StatusPill } from '../../components/StatusPill';

const pipelineStages = [
  'Hugging Face 모델 수신',
  '파일별 분리',
  '가중치 검사',
  'Python 코드 검사',
  'config 검사',
  'A/B-1/B-2/C 등급',
  '최종 릴리스 판정',
];

const intakeFlow = [
  {
    icon: PackageSearch,
    title: '모델 수신',
    detail: 'Hugging Face repo snapshot에서 파일 목록, 크기, 해시를 수집합니다.',
  },
  {
    icon: GitBranch,
    title: '파일별 분리',
    detail: '가중치, Python 코드, config를 서로 다른 검증기로 보냅니다.',
  },
  {
    icon: ShieldCheck,
    title: '독립 검사',
    detail: '각 파일 결과는 artifact status로 따로 기록됩니다.',
  },
  {
    icon: ArrowRight,
    title: '최종 결론',
    detail: '모든 artifact 결과를 합쳐 job decision을 계산합니다.',
  },
];

const fileLanes = [
  {
    icon: FileArchive,
    title: '가중치 파일',
    examples: 'safetensors, pickle, bin',
    checks: [
      'safetensors: 메타데이터와 SHA-256 검증',
      'pickle Path A: 실행 없이 opcode와 tensor schema 검사',
      '필요 시 Path B: sandbox/gVisor 비교 근거 수집',
    ],
    outcome: 'PASS, BLOCK, 또는 safetensors 변환 후 승인',
  },
  {
    icon: FileCode2,
    title: 'Python 파일',
    examples: 'modeling_*.py, tokenizer/processor 코드',
    checks: [
      '역할 분류 후 AST/API/context 검사',
      '위험 import/call/API는 즉시 차단 후보',
      '안전 후보는 제한 런타임 또는 보안 담당자 게이트로 이동',
    ],
    outcome: 'A / B-1 / B-2 / C 등급',
  },
  {
    icon: Settings,
    title: 'config 파일',
    examples: 'config.json, auto_map, tokenizer config',
    checks: [
      'schema와 trigger 필드 검사',
      'auto_map이 가리키는 Python 파일을 연결 검사로 승격',
      'config 자체 결과와 연결 코드 결과를 함께 반영',
    ],
    outcome: 'PASS, BLOCK, 또는 PENDING_REVIEW',
  },
];

const gradeCards = [
  {
    grade: 'A',
    title: '재생성 가능',
    status: 'PASS',
    action: 'AUTO_APPROVE_REGENERATED',
    detail: '원본 코드를 실행하지 않고 정적 형태를 재생성해 검증 가능한 경우입니다.',
  },
  {
    grade: 'B-1',
    title: '제한 런타임 통과',
    status: 'PASS',
    action: 'AUTO_APPROVE',
    detail: '정형 modeling 코드가 허용 API만 쓰고 제한 런타임 gate를 통과한 경우입니다.',
  },
  {
    grade: 'B-2',
    title: '보안 담당자 게이트',
    status: 'PENDING_REVIEW',
    action: 'SECURITY_OWNER_GATE',
    detail: '미등록 API, 문맥 검토, sandbox/gVisor 근거가 필요한 경우입니다.',
  },
  {
    grade: 'C',
    title: '수동 검토/차단',
    status: 'PENDING_REVIEW 또는 BLOCK',
    action: 'MANUAL_REVIEW_REQUIRED / BLOCK_IMMEDIATELY',
    detail: '위험 호출, 동적/난독화 패턴, 의미가 불명확한 코드가 포함된 경우입니다.',
  },
];

function okTone(ok: boolean) {
  return ok ? 'ok' : 'bad';
}

function gradeTone(grade: string): 'ok' | 'warn' | 'bad' | 'info' {
  if (grade === 'A' || grade === 'B-1') return 'ok';
  if (grade === 'B-2') return 'warn';
  return 'bad';
}

export function OverviewPage() {
  const { data, error, isLoading } = useQuery({
    queryKey: ['overview'],
    queryFn: fetchOverviewData,
  });

  if (isLoading) {
    return (
      <section className="console-panel" aria-busy="true">
        <div className="section-kicker">준비 상태</div>
        <h1>시스템 개요</h1>
        <div className="loading-line" />
        <div className="loading-grid">
          <div />
          <div />
          <div />
          <div />
        </div>
      </section>
    );
  }

  if (error || !data) {
    return (
      <section className="console-panel">
        <div className="section-kicker">준비 상태</div>
        <h1>시스템 개요</h1>
        <ErrorPanel
          title="개요 데이터를 불러올 수 없습니다"
          message={error instanceof Error ? error.message : '개요 요청이 완료되지 않았습니다.'}
        />
      </section>
    );
  }

  const { health, readiness, stats } = data;
  const missing = readiness.evidence.missing;
  const warnings = readiness.warnings;

  return (
    <section className="console-panel overview-panel" aria-labelledby="overview-title">
      <div className="section-kicker">준비 상태</div>
      <div className="overview-heading">
        <div>
          <h1 id="overview-title">시스템 개요</h1>
          <p>Hugging Face 모델을 파일 종류별로 분리해 검증하고, Python 코드는 A/B-1/B-2/C 등급으로 판정합니다.</p>
        </div>
        <div className="run-actions">
          <Link className="primary-link" to="/live">
            <UploadCloud aria-hidden="true" size={16} />
            <span>실제 모델 실행</span>
          </Link>
          <Link className="primary-link" to="/demo">
            <Play aria-hidden="true" size={16} />
            <span>데모 콘솔</span>
          </Link>
        </div>
      </div>

      <div className="readiness-strip" aria-label="준비 상태">
        <StatusPill tone={okTone(health.status === 'ok')}>상태 {health.status === 'ok' ? '정상' : health.status.toUpperCase()}</StatusPill>
        <StatusPill tone={okTone(readiness.openapi.ok)}>OpenAPI {readiness.openapi.ok ? '정상' : '문제'}</StatusPill>
        <StatusPill tone={okTone(readiness.dashboard.ok)}>대시보드 {readiness.dashboard.ok ? '정상' : '문제'}</StatusPill>
        <StatusPill tone={okTone(readiness.audit_chain.valid)}>
          감사 체인 {readiness.audit_chain.valid ? '정상' : '무효'}
        </StatusPill>
        <StatusPill tone={missing.length ? 'warn' : 'ok'}>근거 자료 {missing.length ? `${missing.length}건 누락` : '준비 완료'}</StatusPill>
      </div>

      <section className="flow-section" aria-labelledby="model-flow-title">
        <div className="section-title-row">
          <div>
            <h2 id="model-flow-title">모델 수신 후 검증 흐름</h2>
            <p className="quiet-copy">가중치, Python 파일, config 파일은 같은 모델 안에 있어도 서로 다른 검사 경로를 탑니다.</p>
          </div>
          <StatusPill tone="info">파일별 독립 검사</StatusPill>
        </div>

        <div className="flow-step-row" aria-label="Hugging Face 모델 처리 흐름">
          {intakeFlow.map((step, index) => {
            const Icon = step.icon;
            return (
              <div className="flow-step" key={step.title}>
                <div className="flow-step-icon">
                  <Icon aria-hidden="true" size={18} />
                </div>
                <strong>{step.title}</strong>
                <span>{step.detail}</span>
                {index < intakeFlow.length - 1 ? <ArrowRight aria-hidden="true" className="flow-step-arrow" size={16} /> : null}
              </div>
            );
          })}
        </div>

        <div className="file-lane-grid">
          {fileLanes.map((lane) => {
            const Icon = lane.icon;
            return (
              <section className="file-lane" key={lane.title} aria-label={`${lane.title} 검사 흐름`}>
                <div className="lane-heading">
                  <Icon aria-hidden="true" size={20} />
                  <div>
                    <h3>{lane.title}</h3>
                    <span>{lane.examples}</span>
                  </div>
                </div>
                <ol>
                  {lane.checks.map((check) => (
                    <li key={check}>{check}</li>
                  ))}
                </ol>
                <div className="lane-outcome">
                  <span>결과</span>
                  <strong>{lane.outcome}</strong>
                </div>
              </section>
            );
          })}
        </div>

        <div className="grade-grid" aria-label="Python 코드 등급 설명">
          {gradeCards.map((item) => (
            <div className="grade-card" key={item.grade}>
              <div className="grade-card-heading">
                <StatusPill tone={gradeTone(item.grade)}>{item.grade}</StatusPill>
                <strong>{item.title}</strong>
              </div>
              <dl>
                <div>
                  <dt>상태</dt>
                  <dd>{item.status}</dd>
                </div>
                <div>
                  <dt>조치</dt>
                  <dd>{item.action}</dd>
                </div>
              </dl>
              <p>{item.detail}</p>
            </div>
          ))}
        </div>

        <p className="flow-note">
          주의: A/B-1/B-2/C는 Python 코드 등급입니다. 최종 릴리스 결론은 모든 artifact status를 합쳐 별도의 job decision으로 계산됩니다.
        </p>
      </section>

      <div className="metric-grid metric-grid-four" aria-label="화이트리스트 지표">
        <MetricTile label="승인 API" value={stats.approved_active} detail={`버전 ${stats.whitelist_version}`} />
        <MetricTile label="검토 대기" value={stats.pending_review} detail="보안 담당자 검토 대기열" />
        <MetricTile label="차단 API" value={stats.blocked} detail="릴리스 거부 경로" />
        <MetricTile label="피드백 제보" value={stats.feedback_total} detail="운영자 제출 건수" />
      </div>

      <div className="overview-grid">
        <section className="section-block" aria-labelledby="pipeline-title">
          <div className="section-title-row">
            <h2 id="pipeline-title">검증 파이프라인</h2>
            <StatusPill tone="info">고정 시나리오 모드</StatusPill>
          </div>
          <ol className="pipeline-list">
            {pipelineStages.map((stage, index) => (
              <li key={stage}>
                <span>{stage}</span>
                {index < pipelineStages.length - 1 ? <ArrowRight aria-hidden="true" size={15} /> : null}
              </li>
            ))}
          </ol>
        </section>

        <section className="section-block" aria-labelledby="readiness-title">
          <div className="section-title-row">
            <h2 id="readiness-title">준비 상태 메모</h2>
            <a href="/docs" target="_blank" rel="noreferrer" className="icon-link" aria-label="Swagger 문서 열기">
              <ExternalLink aria-hidden="true" size={17} />
            </a>
          </div>
          {warnings.length ? (
            <ul className="notice-list">
              {warnings.map((warning) => (
                <li key={warning}>
                  <AlertTriangle aria-hidden="true" size={16} />
                  <span>{warning}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="quiet-copy">보고된 준비 상태 경고가 없습니다.</p>
          )}
          {missing.length ? (
            <div className="missing-evidence">
              <strong>누락된 근거 자료</strong>
              <ul>
                {missing.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="quiet-copy">추적 중인 근거 자료 파일이 모두 있습니다.</p>
          )}
        </section>
      </div>
    </section>
  );
}
