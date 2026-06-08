import { API_BASE } from '../api/client';

const sections = {
  overview: {
    eyebrow: '준비 상태',
    title: '시스템 개요',
    body: '상태, 화이트리스트 지표, 데모 준비 상태, 파이프라인 상태입니다.',
  },
  demo: {
    eyebrow: '고정 시나리오',
    title: '데모 콘솔',
    body: '시나리오 실행, 기대값 일치 여부, 산출물 근거입니다.',
  },
  validation: {
    eyebrow: '검증',
    title: '검증 상세',
    body: '작업 판정, 산출물 상태, 사유 항목, 생성 산출물입니다.',
  },
  operations: {
    eyebrow: '운영',
    title: '화이트리스트 운영',
    body: '화이트리스트 확인, 검토 대기열, 감사 검증, 피드백입니다.',
  },
  evidence: {
    eyebrow: '근거 자료',
    title: '근거 자료 매트릭스',
    body: '문서, 작업 기록, 테스트 근거, 알려진 한계입니다.',
  },
};

export type ConsoleSection = keyof typeof sections;

type PlaceholderPageProps = {
  section: ConsoleSection;
};

export function PlaceholderPage({ section }: PlaceholderPageProps) {
  const item = sections[section];
  return (
    <section className="console-panel" aria-labelledby={`${section}-title`}>
      <div className="section-kicker">{item.eyebrow}</div>
      <h1 id={`${section}-title`}>{item.title}</h1>
      <p>{item.body}</p>
      <div className="metric-grid" aria-label={`${item.title} 요약`}>
        <div className="metric-tile">
          <span>API 기준 경로</span>
          <strong>{API_BASE}</strong>
        </div>
        <div className="metric-tile">
          <span>라우트</span>
          <strong>{section}</strong>
        </div>
        <div className="metric-tile">
          <span>단계</span>
          <strong>Phase 2</strong>
        </div>
      </div>
    </section>
  );
}
