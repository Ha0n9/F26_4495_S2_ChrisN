import { Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { CoverageRow } from '@/types/view';

const { Paragraph, Text } = Typography;

const STATUS_COLOR: Record<CoverageRow['status'], string> = {
  Completed: 'green',
  // Orange rather than green, because a reader scanning this column for
  // problems must not pass over a check that stopped short of its ground.
  Partial: 'orange',
  Failed: 'red',
  'Not run': 'default',
};

const STATUS_LABEL: Record<CoverageRow['status'], string> = {
  Completed: 'Completed',
  Partial: 'Partial',
  Failed: 'Failed',
  'Not run': 'Not run',
};

export function CoverageTab({ rows }: { rows: CoverageRow[] }) {
  const columns: ColumnsType<CoverageRow> = [
    {
      title: 'Check',
      dataIndex: 'name',
      key: 'name',
      render: (value: string, row) => (
        <Space direction="vertical" size={0}>
          <Text>{value}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {row.checkId}
          </Text>
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      render: (value: CoverageRow['status']) => (
        <Tag color={STATUS_COLOR[value]}>{STATUS_LABEL[value]}</Tag>
      ),
    },
    {
      title: 'Findings',
      dataIndex: 'findingCount',
      key: 'findingCount',
      width: 100,
      align: 'right',
      render: (value: number | null) => (value === null ? <Text type="secondary">Unknown</Text> : value),
    },
    {
      title: 'Detail',
      dataIndex: 'errorMessage',
      key: 'errorMessage',
      render: (value: string | undefined, row) => {
        if (value) return <Text type="danger">{value}</Text>;
        // The reason a check stopped short is the actionable part: it names
        // the branch that was skipped and the parameter that would include
        // it, so it is shown rather than summarised.
        if (row.partialReason) return <Text type="warning">{row.partialReason}</Text>;
        // This column is about whether the check ran, not about what it
        // found. Saying "no issues" here contradicts the Findings column
        // beside it whenever a completed check reported something.
        return (
          <Text type="secondary">
            {row.status === 'Completed' ? 'Ran without error' : 'Not attempted'}
          </Text>
        );
      },
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Paragraph type="secondary" style={{ marginBottom: 0 }}>
        A check that failed is not the same as a check that found nothing, and a check marked Partial is neither. It
        ran to the end without error but stopped short of some of the ground it covers, so what it reported is real
        and what it did not reach is unknown. The Detail column says what was skipped and which setting would include
        it.
      </Paragraph>
      <div className="scroll-x">
        <Table<CoverageRow>
          size="small"
          columns={columns}
          dataSource={rows}
          pagination={false}
          scroll={{ x: 'max-content' }}
        />
      </div>
    </Space>
  );
}
