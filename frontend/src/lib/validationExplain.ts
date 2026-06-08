import type {
  ArtifactValidationResult,
  ReasonEntry,
  ValidationJobResponse,
} from '../api/types';
import {
  koreanFileKindLabel,
  koreanReasonCodeDetail,
  koreanReasonCodeTitle,
  koreanReleaseActionLabel,
  koreanReviewActionLabel,
  koreanRouteKindLabel,
  koreanStatusLabel,
} from './koreanLabels';

export function validationDecisionSummary(response: ValidationJobResponse): string {
  const total = response.artifact_results.length;
  const blocked = response.blocked_artifact_ids.length;
  const pending = response.pending_artifact_ids.length;
  const approved = response.approved_artifact_ids.length;

  if (response.overall_decision === 'DENY') {
    return `총 ${total}개 파일 중 ${blocked}개가 차단되어 이 모델은 릴리스할 수 없습니다.`;
  }
  if (response.overall_decision === 'REVIEW_REQUIRED') {
    return `총 ${total}개 파일 중 ${pending}개가 검토 대상입니다. 자동 승인하지 않고 보안 담당자 확인으로 넘깁니다.`;
  }
  if (response.overall_decision === 'APPROVE_WITH_TRANSFORM') {
    return `총 ${total}개 파일을 검사했고, 원본 대신 안전한 변환 산출물을 승인 대상으로 봅니다.`;
  }
  if (response.overall_decision === 'APPROVE') {
    return `총 ${total}개 파일을 검사했고 ${approved}개가 승인 흐름으로 들어갈 수 있습니다.`;
  }
  return `총 ${total}개 파일 중 오류가 있어 결과를 확정할 수 없습니다.`;
}

export function artifactPlainSummary(result: ArtifactValidationResult): string {
  const kind = koreanFileKindLabel(result.artifact.file_kind);
  const route = koreanRouteKindLabel(result.route_kind);
  const status = koreanStatusLabel(result.status);
  const reasons = result.reason_entries.map((entry) => koreanReasonCodeTitle(entry.code));
  const reasonText = reasons.length ? reasons.join(', ') : '추가 사유 없음';

  if (result.status === 'PASS') {
    return `${kind}인 ${result.artifact.repo_path} 파일은 ${route}에서 ${status}했습니다. 핵심 근거는 ${reasonText}입니다.`;
  }
  if (result.status === 'BLOCK') {
    return `${kind}인 ${result.artifact.repo_path} 파일은 ${route}에서 차단됐습니다. 핵심 사유는 ${reasonText}입니다.`;
  }
  if (result.status === 'PENDING_REVIEW') {
    return `${kind}인 ${result.artifact.repo_path} 파일은 ${route}에서 자동 승인하기 어렵다고 판단됐습니다. 핵심 사유는 ${reasonText}입니다.`;
  }
  if (result.status === 'SKIPPED') {
    return `${kind}인 ${result.artifact.repo_path} 파일은 현재 경로에서 직접 검증되지 않았습니다. 핵심 사유는 ${reasonText}입니다.`;
  }
  return `${kind}인 ${result.artifact.repo_path} 파일은 ${route}에서 오류가 발생했습니다. 핵심 사유는 ${reasonText}입니다.`;
}

export function artifactNextAction(result: ArtifactValidationResult): string {
  if (result.status === 'PASS') {
    if (result.review_action === 'AUTO_APPROVE_REGENERATED') {
      return '원본을 그대로 신뢰하지 않고 재생성 또는 변환 산출물을 승인 후보로 봅니다.';
    }
    return '추가 차단 없이 승인 후보로 볼 수 있습니다.';
  }
  if (result.status === 'BLOCK') {
    return '릴리스 대상에서 제외하고, 차단 사유를 발표에서 명확히 보여줘야 합니다.';
  }
  if (result.review_action === 'SECURITY_OWNER_GATE') {
    return '보안 담당자 검토가 끝나기 전에는 승인하면 안 됩니다.';
  }
  if (result.review_action === 'MANUAL_REVIEW_REQUIRED') {
    return '자동 판정이 어렵기 때문에 사람이 직접 코드와 근거를 확인해야 합니다.';
  }
  if (result.status === 'ERROR') {
    return '검증 환경 또는 입력 파일 문제를 먼저 해결해야 합니다.';
  }
  return koreanReviewActionLabel(result.review_action);
}

export function reasonExplanation(entry: ReasonEntry): string {
  return koreanReasonCodeDetail(entry.code);
}

export function artifactFactRows(result: ArtifactValidationResult): Array<[string, string]> {
  return [
    ['파일 종류', koreanFileKindLabel(result.artifact.file_kind)],
    ['검사 경로', koreanRouteKindLabel(result.route_kind)],
    ['상태', koreanStatusLabel(result.status)],
    ['등급', String(result.grade)],
    ['검토 조치', koreanReviewActionLabel(result.review_action)],
  ];
}

export function responseFactRows(response: ValidationJobResponse): Array<[string, string]> {
  return [
    ['작업 판정', koreanStatusLabel(response.overall_decision)],
    ['산출물 상태', koreanStatusLabel(response.overall_status)],
    ['릴리스 조치', koreanReleaseActionLabel(response.release_action)],
    ['승인 후보', `${response.approved_artifact_ids.length}개`],
    ['검토 대기', `${response.pending_artifact_ids.length}개`],
    ['차단', `${response.blocked_artifact_ids.length}개`],
  ];
}
