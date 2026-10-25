import { Button, InputNumber, Space, Tooltip, Typography, Upload } from 'antd';
import type { UploadProps } from 'antd';
import { useState } from 'react';
import { apiAvailable } from '@/lib/api';

const { Text } = Typography;

interface Props {
  onScanFile: (file: File) => void;
  onDictionaryFile: (file: File) => void;
  onReload: () => void;
  onRunScan: (newAccountGraceDays: number) => void;
  busy: boolean;
  scanning: boolean;
}

/**
 * The scan is started from here, which is the point of the local API: an
 * administrator should not have to leave the interface, run a command and
 * come back.
 *
 * Opening a file by hand remains, because a scan result is often reviewed on
 * a machine that never ran it.
 */
export function DataSourceBar({
  onScanFile,
  onDictionaryFile,
  onReload,
  onRunScan,
  busy,
  scanning,
}: Props) {
  // Freshly created accounts are excused for not having signed in yet. A test
  // lab seeded minutes ago needs that grace set to zero, which is why it is
  // adjustable here rather than buried in the module.
  const [graceDays, setGraceDays] = useState<number>(30);

  const common: Partial<UploadProps> = { accept: '.json', showUploadList: false };

  return (
    <Space wrap size={8}>
      {apiAvailable && (
        <>
          <Button type="primary" loading={scanning} onClick={() => onRunScan(graceDays)}>
            {scanning ? 'Scanning the domain' : 'Run scan'}
          </Button>
          <Tooltip title="How recently an account can have been created and still be excused for never signing in. Set to 0 on a freshly seeded lab.">
            <Space size={4}>
              <Text type="secondary">New account grace</Text>
              <InputNumber
                min={0}
                max={365}
                value={graceDays}
                onChange={(value) => setGraceDays(value ?? 0)}
                disabled={scanning}
                style={{ width: 80 }}
              />
              <Text type="secondary">days</Text>
            </Space>
          </Tooltip>
        </>
      )}

      <Upload
        {...common}
        beforeUpload={(file) => {
          onScanFile(file as unknown as File);
          return false;
        }}
      >
        <Button disabled={scanning}>Open a scan file</Button>
      </Upload>

      <Upload
        {...common}
        beforeUpload={(file) => {
          onDictionaryFile(file as unknown as File);
          return false;
        }}
      >
        <Button disabled={scanning}>Open a dictionary file</Button>
      </Upload>

      <Button onClick={onReload} loading={busy && !scanning} disabled={scanning}>
        Reload
      </Button>

      {!apiAvailable && (
        <Text type="secondary">
          Reading files directly. Start the local server and open the link it prints to run scans from here.
        </Text>
      )}
    </Space>
  );
}
