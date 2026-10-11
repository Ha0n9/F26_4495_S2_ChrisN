import { Tag, Typography } from 'antd';
import type { AttributeValue as AttributeValueType } from '@/types/scan';

const { Text } = Typography;

/** Renders one attribute value consistently wherever it appears. */
export function AttributeValue({ value }: { value: AttributeValueType | undefined }) {
  if (value === null || value === undefined) {
    return <Text type="secondary">Not set</Text>;
  }
  if (typeof value === 'boolean') {
    return <Tag color={value ? 'green' : 'default'}>{value ? 'Yes' : 'No'}</Tag>;
  }
  if (Array.isArray(value)) {
    return value.length ? <>{value.join(', ')}</> : <Text type="secondary">None</Text>;
  }
  if (typeof value === 'object') {
    return <>{JSON.stringify(value)}</>;
  }
  return <>{String(value)}</>;
}
