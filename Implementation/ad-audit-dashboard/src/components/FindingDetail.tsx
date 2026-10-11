import { Alert, Badge, Button, Descriptions, List, Space, Typography } from 'antd';
import { useState } from 'react';
import { AffectedObjectsTable } from './AffectedObjectsTable';
import { AttributeValue } from './AttributeValue';
import { labelize } from '@/lib/format';
import type { FindingRow } from '@/types/view';

const { Link, Paragraph, Text } = Typography;

/**
 * Expanded row content. Nothing here is wrapped in a container component:
 * tables and description lists sit directly in the row.
 */
export function FindingDetail({ row }: { row: FindingRow }) {
  const [showRaw, setShowRaw] = useState(false);
  const { finding, entry } = row;

  const evidence = finding.evidence ?? {};
  const evidenceItems = Object.entries(evidence)
    .filter(([key]) => key !== 'summary')
    .map(([key, value]) => ({
      key,
      label: labelize(key),
      children: <AttributeValue value={value ?? null} />,
    }));

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="Why this matters"
        description={entry?.whyItMatters ?? 'This check is not described in the finding dictionary yet.'}
      />

      <div>
        <Text strong>What to do</Text>
        {entry?.whatToDo?.length ? (
          <List
            size="small"
            style={{ marginTop: 8 }}
            dataSource={entry.whatToDo}
            renderItem={(step, index) => (
              <List.Item>
                <Space align="start">
                  <Badge count={index + 1} color="blue" />
                  <Text>{step}</Text>
                </Space>
              </List.Item>
            )}
          />
        ) : (
          <Paragraph type="secondary" style={{ marginTop: 8 }}>
            No remediation guidance is recorded for this check.
          </Paragraph>
        )}
      </div>

      <div>
        <Text strong>Affected objects ({finding.affectedObjectCount})</Text>
        <div style={{ marginTop: 8 }}>
          <AffectedObjectsTable
            objects={finding.affectedObjects}
            keyAttributes={entry?.keyAttributes ?? []}
            objectColumnLabel={entry?.objectColumnLabel ?? 'Object'}
          />
        </div>
      </div>

      <div>
        <Text strong>Evidence</Text>
        <Paragraph style={{ marginTop: 8, marginBottom: 8 }}>
          {evidence.summary ?? 'No summary was recorded for this finding.'}
        </Paragraph>
        {evidenceItems.length > 0 && <Descriptions size="small" column={1} bordered items={evidenceItems} />}
      </div>

      {entry?.references?.length ? (
        <div>
          <Text strong>Reference</Text>
          <div style={{ marginTop: 8 }}>
            {entry.references.map((reference) => (
              <div key={reference.url}>
                <Link href={reference.url} target="_blank" rel="noreferrer">
                  {reference.label}
                </Link>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <div>
        <Button size="small" onClick={() => setShowRaw((open) => !open)}>
          {showRaw ? 'Hide raw finding' : 'Show raw finding'}
        </Button>
        {showRaw && (
          <div className="scroll-x" style={{ marginTop: 8 }}>
            <pre className="raw-json">{JSON.stringify(finding, null, 2)}</pre>
          </div>
        )}
      </div>
    </Space>
  );
}
