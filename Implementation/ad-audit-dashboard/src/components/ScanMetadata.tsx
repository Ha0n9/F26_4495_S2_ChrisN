import { Descriptions, Typography } from 'antd';
import { AttributeValue } from './AttributeValue';
import { formatTimestamp } from '@/lib/format';
import type { ScanMeta } from '@/types/scan';

const { Text } = Typography;

export function ScanMetadata({ meta }: { meta: ScanMeta }) {
  const items = [
    { key: 'domain', label: 'Domain', children: meta.domain.dnsName },
    { key: 'netbios', label: 'NetBIOS name', children: meta.domain.netbiosName ?? 'Unknown' },
    { key: 'dc', label: 'Domain controller', children: meta.domain.domainControllerQueried ?? 'Unknown' },
    { key: 'level', label: 'Functional level', children: meta.domain.domainFunctionalLevel ?? 'Unknown' },
    { key: 'started', label: 'Scan started', children: formatTimestamp(meta.startedAt) },
    { key: 'completed', label: 'Scan completed', children: formatTimestamp(meta.completedAt) },
    { key: 'module', label: 'Module', children: `${meta.moduleName} ${meta.moduleVersion}` },
    { key: 'account', label: 'Run as', children: meta.executedBy?.account ?? 'Unknown' },
    {
      key: 'rights',
      label: 'Domain admin rights',
      children: <AttributeValue value={meta.executedBy?.hadDomainAdminRights ?? null} />,
    },
    {
      key: 'scanId',
      label: 'Scan ID',
      children: <Text style={{ fontSize: 12 }}>{meta.scanId}</Text>,
    },
  ];

  return <Descriptions size="small" bordered column={{ xs: 1, sm: 2, md: 3 }} items={items} />;
}
