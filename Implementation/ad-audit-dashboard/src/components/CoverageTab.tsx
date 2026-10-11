import { Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { CoverageRow } from '@/types/view';

const { Paragraph, Text } = Typography;

const STATUS_COLOR: Record<CoverageRow['status'], string> = {
  Completed: 'green',
  Failed: 'red',
  'Not run': 'default',
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
      render: (value: CoverageRow['status']) => <Tag color={STATUS_COLOR[value]}>{value}</Tag>,
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
      render: (value?: string) =>
        value ? <Text type="danger">{value}</Text> : <Text type="secondary">No issues reported</Text>,
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Paragraph type="secondary" style={{ marginBottom: 0 }}>
        A check that failed is not the same as a check that found nothing. Failed checks left part of this domain
        unexamined.
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
