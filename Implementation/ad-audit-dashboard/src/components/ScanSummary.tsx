import { Card, Col, Progress, Row, Space, Statistic, Tooltip, Typography } from 'antd';
import { scoreCaption, scoreStatus, securityScore } from '@/lib/score';
import { SEVERITIES, type Severity } from '@/types/scan';
import type { ScanResult } from '@/types/scan';
import type { FindingRow } from '@/types/view';

const { Text } = Typography;

/** The only Card on the page. Statistics sit directly inside it. */
export function ScanSummary({ scan, rows }: { scan: ScanResult; rows: FindingRow[] }) {
  const counts = SEVERITIES.reduce(
    (acc, severity) => ({ ...acc, [severity]: rows.filter((r) => r.severity === severity).length }),
    {} as Record<Severity, number>,
  );

  const objectsAffected = rows.reduce((total, row) => total + row.objectCount, 0);
  const score = securityScore(scan);

  return (
    <Card size="small">
      <Row gutter={[16, 16]} align="middle">
        <Col xs={24} sm={12} md={6}>
          <Space direction="vertical" size={4}>
            <Text type="secondary">Security score</Text>
            <Tooltip title={scoreCaption(score)}>
              <Progress
                type="dashboard"
                percent={score.value ?? 0}
                size={100}
                status={scoreStatus(score.value)}
                // A scan that examined nothing has no score. Showing 100 here
                // would contradict the Coverage tab sitting next to it.
                format={() => (score.value === null ? 'n/a' : score.value)}
              />
            </Tooltip>
            <Text type={score.partial ? 'warning' : 'secondary'} style={{ fontSize: 12 }}>
              {scoreCaption(score)}
            </Text>
          </Space>
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic title="Critical" value={counts.Critical} valueStyle={{ color: '#cf1322' }} />
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic title="High" value={counts.High} valueStyle={{ color: '#d4380d' }} />
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic title="Medium" value={counts.Medium} />
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic title="Low" value={counts.Low} />
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic title="Objects affected" value={objectsAffected} />
        </Col>
        <Col xs={12} sm={6} md={3}>
          <Statistic
            title="Checks completed"
            value={score.checksCompleted}
            suffix={`/ ${score.checksRequested}`}
            valueStyle={score.partial ? { color: '#d46b08' } : undefined}
          />
        </Col>
      </Row>
    </Card>
  );
}
