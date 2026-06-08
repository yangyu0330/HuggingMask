import { useQuery } from '@tanstack/react-query';
import { Archive, FileText, RefreshCw } from 'lucide-react';

import { getDemoEvidence } from '../../api/demo';
import { getDemoReadiness } from '../../api/ops';
import type { DemoEvidenceItem } from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { StatusPill } from '../../components/StatusPill';
import { koreanEvidenceKindLabel, koreanPresentMissing } from '../../lib/koreanLabels';

const documentPaths = [
  {
    title: 'README',
    path: 'README.md',
    note: '프로젝트 범위, 실행 명령, 발표 상태 요약입니다.',
  },
  {
    title: '설치 가이드',
    path: 'SETUP_GUIDE.md',
    note: '로컬 Python, Docker, 포트, 테스트 준비 체크리스트입니다.',
  },
  {
    title: '상세 설치 가이드',
    path: 'docs/setup_guide.md',
    note: '개발자용 설정 메모와 명령어 참고 자료입니다.',
  },
  {
    title: '최종 데모 스크립트',
    path: 'docs/final_demo_script.md',
    note: '4-6분 발표 흐름과 시나리오 설명 포인트입니다.',
  },
  {
    title: '프론트엔드 콘솔 설계안',
    path: 'docs/frontend_demo_console_blueprint.md',
    note: 'React 콘솔과 지원 API의 설계 계획입니다.',
  },
];

const limitationItems = [
  {
    title: 'B-2/gVisor',
    body: 'Path B는 선택적으로 켜는 근거입니다. 기본 fixture 데모가 gVisor를 항상 실행한다고 주장하지 않습니다.',
  },
  {
    title: '테스트 범위',
    body: '이 단계에서는 집중 빌드와 pytest 확인을 사용했습니다. 전체 테스트 근거는 별도로 보관되어 있으며 최종 전체 검증은 Phase 7 범위입니다.',
  },
  {
    title: '실제 Hugging Face',
    body: '안정적인 기본 경로는 fixture 시나리오입니다. 실제 HF 다운로드는 선택 근거이며 운영용 크롤러를 주장하지 않습니다.',
  },
  {
    title: '운영 범위',
    body: '이 데모 콘솔에는 역할 기반 로그인이 없습니다. 검토 조치는 로컬 운영 API를 통해 보여줍니다.',
  },
];

const presentationSteps = ['개요', '데모 콘솔', '검증 상세', '운영 관리', '근거 자료'];

function statusTone(item: DemoEvidenceItem): 'ok' | 'warn' {
  return item.exists ? 'ok' : 'warn';
}

function formatDate(value: string | null) {
  if (!value) return '누락';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('ko-KR');
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export function EvidencePage() {
  const evidenceQuery = useQuery({ queryKey: ['demo', 'evidence'], queryFn: getDemoEvidence });
  const readinessQuery = useQuery({ queryKey: ['demo', 'readiness'], queryFn: getDemoReadiness });

  const evidenceItems = evidenceQuery.data?.items ?? [];
  const missing = readinessQuery.data?.evidence.missing ?? [];

  return (
    <section className="console-panel evidence-panel" aria-labelledby="evidence-title">
      <div className="section-kicker">근거 자료</div>
      <div className="overview-heading">
        <div>
          <h1 id="evidence-title">근거 자료 매트릭스</h1>
          <p>설계 문서, 데모 스크립트, 작업 기록, 테스트 로그, 누락 파일, 발표 한계를 한곳에서 확인합니다.</p>
        </div>
        <StatusPill tone={missing.length ? 'warn' : 'ok'}>
          {missing.length ? `${missing.length}건 누락` : '근거 자료 있음'}
        </StatusPill>
      </div>

      {(evidenceQuery.error || readinessQuery.error) ? (
        <ErrorPanel
          title="근거 자료 데이터를 불러올 수 없습니다"
          message={errorMessage(evidenceQuery.error ?? readinessQuery.error)}
        />
      ) : null}

      <section className="section-block" aria-labelledby="matrix-title">
        <div className="section-title-row">
          <div>
            <h2 id="matrix-title">파일과 상태</h2>
            <p className="quiet-copy">GET /internal/v1/demo/evidence</p>
          </div>
          <button type="button" className="primary-link" onClick={() => evidenceQuery.refetch()}>
            <RefreshCw aria-hidden="true" size={16} />
            <span>새로고침</span>
          </button>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>종류</th>
                <th>제목</th>
                <th>경로</th>
                <th>상태</th>
                <th>마지막 수정</th>
                <th>사유</th>
              </tr>
            </thead>
            <tbody>
              {evidenceItems.map((item) => (
                <tr key={`${item.kind}-${item.path}`}>
                  <td>{koreanEvidenceKindLabel(item.kind)}</td>
                  <td>{item.title}</td>
                  <td><code>{item.path}</code></td>
                  <td><StatusPill tone={statusTone(item)}>{koreanPresentMissing(item.exists)}</StatusPill></td>
                  <td>{formatDate(item.last_modified)}</td>
                  <td>{item.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="evidence-grid">
        <section className="section-block" aria-labelledby="missing-title">
          <div className="section-title-row">
            <h2 id="missing-title">누락된 근거 자료</h2>
            <StatusPill tone={missing.length ? 'warn' : 'ok'}>{missing.length ? '검토 필요' : '이상 없음'}</StatusPill>
          </div>
          {missing.length ? (
            <ul className="notice-list">
              {missing.map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : (
            <p className="quiet-copy">설정된 매트릭스 기준으로 누락된 근거 자료가 없습니다.</p>
          )}
        </section>

        <section className="section-block" aria-labelledby="documents-title">
          <h2 id="documents-title">데모 문서</h2>
          <ul className="document-list">
            {documentPaths.map((item) => (
              <li key={item.path}>
                <FileText aria-hidden="true" size={17} />
                <div>
                  <strong>{item.title}</strong>
                  <code>{item.path}</code>
                  <span>{item.note}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="section-block" aria-labelledby="limits-title">
          <div className="section-title-row">
            <h2 id="limits-title">알려진 한계</h2>
            <StatusPill tone="info">과장 없음</StatusPill>
          </div>
          <div className="limitations-list">
            {limitationItems.map((item) => (
              <div key={item.title}>
                <strong>{item.title}</strong>
                <span>{item.body}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="section-block" aria-labelledby="flow-title">
          <h2 id="flow-title">발표 흐름</h2>
          <ol className="presentation-flow">
            {presentationSteps.map((step, index) => (
              <li key={step}>
                <span>{index + 1}</span>
                <strong>{step}</strong>
              </li>
            ))}
          </ol>
          <div className="inline-result">
            <Archive aria-hidden="true" size={18} />
            <span>위의 최종 데모 스크립트 경로를 발표자 체크리스트로 사용하세요.</span>
          </div>
        </section>
      </div>
    </section>
  );
}
