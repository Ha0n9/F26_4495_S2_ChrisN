import { Alert, Badge, ConfigProvider, Skeleton, Space, Tabs, Typography, theme } from 'antd';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { CoverageTab } from './components/CoverageTab';
import { DataSourceBar } from './components/DataSourceBar';
import { FindingsTab } from './components/FindingsTab';
import { RawJsonTab } from './components/RawJsonTab';
import { ScanMetadata } from './components/ScanMetadata';
import { ScanSummary } from './components/ScanSummary';
import {
  DataError,
  loadDictionary,
  loadScanResult,
  parseDictionary,
  parseScanResult,
  readJsonFile,
} from './lib/dataSource';
import { buildCoverageRows, buildFindingRows } from './lib/join';
import { usePrefersDark } from './theme/useColorScheme';
import { formatTimestamp } from './lib/format';
import type { FindingDictionary } from './types/dictionary';
import type { ScanResult } from './types/scan';

const { Paragraph, Text, Title } = Typography;

function messageFor(error: unknown): string {
  if (error instanceof DataError) return error.message;
  if (error instanceof Error) return error.message;
  return 'An unexpected error occurred while reading the file.';
}

export default function App() {
  const dark = usePrefersDark();

  const [scan, setScan] = useState<ScanResult | null>(null);
  const [dictionary, setDictionary] = useState<FindingDictionary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextScan, nextDictionary] = await Promise.all([loadScanResult(), loadDictionary()]);
      setScan(nextScan);
      setDictionary(nextDictionary);
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const openScanFile = useCallback(async (file: File) => {
    try {
      setScan(parseScanResult(await readJsonFile(file), file.name));
      setError(null);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }, []);

  const openDictionaryFile = useCallback(async (file: File) => {
    try {
      setDictionary(parseDictionary(await readJsonFile(file), file.name));
      setError(null);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }, []);

  const findingRows = useMemo(
    () => (scan && dictionary ? buildFindingRows(scan, dictionary) : []),
    [scan, dictionary],
  );
  const coverageRows = useMemo(
    () => (scan && dictionary ? buildCoverageRows(scan, dictionary) : []),
    [scan, dictionary],
  );

  const failedCount = scan?.scan.checksFailed.length ?? 0;
  const ready = Boolean(scan && dictionary);

  return (
    <ConfigProvider theme={{ algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm }}>
      <div className="page">
        <Space direction="vertical" size={20} style={{ width: '100%' }}>
          <div>
            <Title level={3} style={{ marginBottom: 4 }}>
              Active Directory security audit
            </Title>
            <Text type="secondary">
              {scan
                ? `Results for ${scan.scan.domain.dnsName}, scanned ${formatTimestamp(scan.scan.completedAt)}`
                : 'Reading the most recent scan from disk'}
            </Text>
          </div>

          <DataSourceBar
            onScanFile={(file) => void openScanFile(file)}
            onDictionaryFile={(file) => void openDictionaryFile(file)}
            onReload={() => void reload()}
            busy={loading}
          />

          {error && (
            <Alert
              type="error"
              showIcon
              closable
              message="That file could not be read"
              description={
                <Space direction="vertical" size={4}>
                  <Text>{error}</Text>
                  <Paragraph type="secondary" style={{ marginBottom: 0 }}>
                    Run a scan to produce public/data/scan-result.json, or open a scan file from anywhere on this
                    machine.
                  </Paragraph>
                </Space>
              }
              onClose={() => setError(null)}
            />
          )}

          {loading && !ready && <Skeleton active paragraph={{ rows: 8 }} />}

          {ready && scan && (
            <>
              {failedCount > 0 && (
                <Alert
                  type="warning"
                  showIcon
                  message={`${failedCount} check${failedCount > 1 ? 's' : ''} could not run`}
                  description="Part of this domain was not examined, so the results below are incomplete. The Coverage tab lists what was missed and why."
                />
              )}

              <ScanSummary scan={scan} rows={findingRows} />
              <ScanMetadata meta={scan.scan} />

              <Tabs
                defaultActiveKey="findings"
                items={[
                  {
                    key: 'findings',
                    label: `Findings (${findingRows.length})`,
                    children: <FindingsTab rows={findingRows} />,
                  },
                  {
                    key: 'coverage',
                    label: (
                      <Space size={6}>
                        Coverage
                        {failedCount > 0 && <Badge count={failedCount} />}
                      </Space>
                    ),
                    children: <CoverageTab rows={coverageRows} />,
                  },
                  {
                    key: 'raw',
                    label: 'Raw JSON',
                    children: <RawJsonTab value={scan} />,
                  },
                ]}
              />
            </>
          )}
        </Space>
      </div>
    </ConfigProvider>
  );
}
