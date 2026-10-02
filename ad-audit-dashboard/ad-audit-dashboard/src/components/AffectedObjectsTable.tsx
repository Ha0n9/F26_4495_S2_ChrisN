import { Descriptions, Space, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo } from 'react';
import { AttributeValue } from './AttributeValue';
import { labelize } from '@/lib/format';
import type { AffectedObject } from '@/types/scan';

const { Text } = Typography;

interface Props {
  objects: AffectedObject[];
  /** Attribute keys promoted to columns, from the dictionary entry. */
  keyAttributes: string[];
  objectColumnLabel: string;
}

export function AffectedObjectsTable({ objects, keyAttributes, objectColumnLabel }: Props) {
  const presentKeys = useMemo(() => {
    const seen = new Set<string>();
    objects.forEach((o) => Object.keys(o.attributes ?? {}).forEach((k) => seen.add(k)));
    return seen;
  }, [objects]);

  const columnKeys = keyAttributes.filter((k) => presentKeys.has(k));
  const remainingKeys = Array.from(presentKeys).filter((k) => !columnKeys.includes(k));

  const columns: ColumnsType<AffectedObject> = [
    {
      title: objectColumnLabel,
      dataIndex: 'name',
      key: 'name',
      fixed: 'left',
      width: 200,
      render: (value: string, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{value}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {row.objectClass}
          </Text>
        </Space>
      ),
    },
    ...columnKeys.map((key) => ({
      title: labelize(key),
      key,
      width: 180,
      render: (_: unknown, row: AffectedObject) => <AttributeValue value={row.attributes?.[key]} />,
    })),
    {
      title: 'Distinguished name',
      dataIndex: 'distinguishedName',
      key: 'distinguishedName',
      width: 340,
      render: (value: string) => (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {value}
        </Text>
      ),
    },
  ];

  return (
    <div className="scroll-x">
      <Table<AffectedObject>
        size="small"
        rowKey={(row) => row.distinguishedName || row.name}
        columns={columns}
        dataSource={objects}
        scroll={{ x: 'max-content' }}
        pagination={objects.length > 10 ? { pageSize: 10, size: 'small' } : false}
        expandable={
          remainingKeys.length
            ? {
                rowExpandable: (row) => Boolean(row.attributes),
                expandedRowRender: (row) => (
                  <Descriptions
                    size="small"
                    column={2}
                    bordered
                    items={remainingKeys.map((key) => ({
                      key,
                      label: labelize(key),
                      children: <AttributeValue value={row.attributes?.[key]} />,
                    }))}
                  />
                ),
              }
            : undefined
        }
      />
    </div>
  );
}
