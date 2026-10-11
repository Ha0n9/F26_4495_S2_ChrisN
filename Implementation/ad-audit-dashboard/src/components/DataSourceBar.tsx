import { Button, Space, Upload } from 'antd';
import type { UploadProps } from 'antd';

interface Props {
  onScanFile: (file: File) => void;
  onDictionaryFile: (file: File) => void;
  onReload: () => void;
  busy: boolean;
}

/**
 * Loading a file is an override for ad hoc review. The normal path is the
 * launcher script writing scan-result.json into the served data folder.
 */
export function DataSourceBar({ onScanFile, onDictionaryFile, onReload, busy }: Props) {
  const common: Partial<UploadProps> = { accept: '.json', showUploadList: false };

  return (
    <Space wrap size={8}>
      <Upload
        {...common}
        beforeUpload={(file) => {
          onScanFile(file as unknown as File);
          return false;
        }}
      >
        <Button>Open a scan file</Button>
      </Upload>
      <Upload
        {...common}
        beforeUpload={(file) => {
          onDictionaryFile(file as unknown as File);
          return false;
        }}
      >
        <Button>Open a dictionary file</Button>
      </Upload>
      <Button onClick={onReload} loading={busy}>
        Reload from disk
      </Button>
    </Space>
  );
}
