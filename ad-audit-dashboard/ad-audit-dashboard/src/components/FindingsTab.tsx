import { Empty, Input, Select, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';
import { FindingDetail } from './FindingDetail';
import { formatTimestamp } from '@/lib/format';
import { SEVERITY_COLOR } from '@/lib/severity';
import { SEVERITIES, type Severity } from '@/types/scan';
import type { FindingRow } from '@/types/view';

const { Text } = Typography;

export function FindingsTab({ rows }: { rows: FindingRow[] }) {
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [search, setSearch] = useState('');

  const categoryOptions = useMemo(
    () => Array.from(new Set(rows.map((row) => row.category))).map((c) => ({ value: c, label: c })),
    [rows],
  );

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    return rows.filter((row) => {
      if (severities.length && !severities.includes(row.severity)) return false;
      if (categories.length && !categories.includes(row.category)) return false;
      if (!query) return true;
      const haystack = [row.title, row.finding.checkId, row.category, JSON.stringify(row.finding.affectedObjects)]
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [rows, severities, categories, search]);

  const columns: ColumnsType<FindingRow> = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 110,
      render: (value: Severity) => <Tag color={SEVERITY_COLOR[value]}>{value}</Tag>,
    },
    {
      title: 'Finding',
      dataIndex: 'title',
      key: 'title',
      render: (value: string, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{value}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {row.finding.checkId}
          </Text>
        </Space>
      ),
    },
    { title: 'Category', dataIndex: 'category', key: 'category', width: 180 },
    {
      title: 'Objects',
      dataIndex: 'objectCount',
      key: 'objectCount',
      width: 100,
      align: 'right',
      sorter: (a, b) => a.objectCount - b.objectCount,
    },
    {
      title: 'Detected',
      key: 'detectedAt',
      width: 180,
      render: (_, row) => (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {formatTimestamp(row.finding.detectedAt)}
        </Text>
      ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space wrap size={8}>
        <Input.Search
          allowClear
          placeholder="Search findings and affected objects"
          style={{ width: 320 }}
          onChange={(event) => setSearch(event.target.value)}
        />
        <Select<Severity[]>
          mode="multiple"
          allowClear
          placeholder="Severity"
          style={{ minWidth: 180 }}
          value={severities}
          onChange={setSeverities}
          options={SEVERITIES.map((s) => ({ value: s, label: s }))}
        />
        <Select<string[]>
          mode="multiple"
          allowClear
          placeholder="Category"
          style={{ minWidth: 200 }}
          value={categories}
          onChange={setCategories}
          options={categoryOptions}
        />
        <Text type="secondary">
          {visible.length} of {rows.length} shown
        </Text>
      </Space>

      <div className="scroll-x">
        <Table<FindingRow>
          columns={columns}
          dataSource={visible}
          pagination={false}
          scroll={{ x: 'max-content' }}
          locale={{
            emptyText: (
              <Empty
                description={
                  rows.length
                    ? 'No findings match these filters. Clear them to see all results.'
                    : 'This scan completed without reporting any findings.'
                }
              />
            ),
          }}
          expandable={{
            expandRowByClick: true,
            expandedRowRender: (row) => <FindingDetail row={row} />,
          }}
        />
      </div>
    </Space>
  );
}
